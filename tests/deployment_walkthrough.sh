#!/usr/bin/env bash
#
# 照 DEPLOYMENT.md §3「部署步骤」1-7 从零走一遍，验证文档本身是可执行的。
#
# 为什么需要这个脚本：部署文档只靠读是审不出来的。这份文档曾经通不过 ——
# `surreal import` 的参数写成了不存在的 `--conn`，schema 被导进
# `ns=production/db=auth` 而应用默认连 `ns=auth/db=main`，
# 于是进程照常启动、/health 照常返回 ok，直到注册第一个管理员时 500。
# 三处失败全是照着文档做出来的，读十遍也发现不了。
#
# 用法：cargo build && ./tests/deployment_walkthrough.sh
# 退出码：0 表示照文档能从零部署到「拿到一个可用的管理员」。
# 从脚本自身位置推导仓库根，与 integration.sh 同一写法。
#
# 这里曾经写死成某台机器上的绝对路径（`/home/ubuntu/…`）。后果不只是
# 「别人跑不了」：`$ROOT/schema.sql` 不存在时 import 失败，而失败被下面的
# `>/dev/null 2>&1` 吞掉，屏幕上只剩「schema.sql 导入失败」，不给原因 ——
# 一个专门用来证明「文档是可执行的」的脚本，自己不可执行，且不说为什么。
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; SP=8123; AP=8203
export no_proxy="localhost,127.0.0.1" NO_PROXY="localhost,127.0.0.1"
WORK="$(mktemp -d)"; FAIL=0
cleanup(){ kill -9 ${AP_PID:-0} ${DB_PID:-0} 2>/dev/null; rm -rf "$WORK"; }; trap cleanup EXIT
step(){ printf '\n\033[1m[步骤 %s]\033[0m %s\n' "$1" "$2"; }
bad(){ FAIL=$((FAIL+1)); printf '  \033[31m✗ %s\033[0m\n' "$1"; }
ok(){ printf '  \033[32m✓ %s\033[0m\n' "$1"; }

step 1 "启动 SurrealDB 并确认可达"
surreal start --bind "127.0.0.1:${SP}" --user root --pass root memory >/dev/null 2>&1 &
DB_PID=$!; disown $DB_PID
for i in $(seq 40); do curl -sSf -o /dev/null --max-time 2 "http://127.0.0.1:${SP}/health" 2>/dev/null && break; sleep 0.5; done
curl -sSf -o /dev/null --max-time 3 "http://127.0.0.1:${SP}/health" 2>/dev/null && ok "SurrealDB OK" || { bad "起不来"; exit 1; }

step 2 "准备环境变量（照文档，含 ns/db）"
export DATABASE_URL=127.0.0.1:${SP}
export DATABASE_NAMESPACE=auth
export DATABASE_NAME=main
export DATABASE_USER=root
export DATABASE_PASS=root
export JWT_SECRET=$(openssl rand -hex 32)
export APP_URL=http://localhost:${AP}
export SMTP_HOST=127.0.0.1
export SMTP_FROM=noreply@example.com
export BIND_ADDR=127.0.0.1:${AP}
ok "已导出（APP_URL 用 loopback，故不需要生产两项）"

step 3 "准备数据库（复用同一组变量）"
# 导入失败必须把 surreal 的原话打出来。以前这两条是 `>/dev/null 2>&1`，
# 于是「OPTION IMPORT 缺失」「文件不存在」「ns/db 打错」三种完全不同的原因
# 在屏幕上长得一模一样：一句「导入失败」。而这个脚本存在的全部意义，
# 就是让照文档做不出来的时候能立刻知道是哪一步、为什么。
import_sql() {
    local file="$1"
    if surreal import --endpoint "http://$DATABASE_URL" \
        --user "$DATABASE_USER" --pass "$DATABASE_PASS" \
        --namespace "$DATABASE_NAMESPACE" --database "$DATABASE_NAME" \
        "$ROOT/$file" > "$WORK/import.log" 2>&1
    then
        ok "$file 导入成功"
    else
        bad "$file 导入失败"
        sed 's/^/      /' "$WORK/import.log" >&2
    fi
}
import_sql schema.sql
import_sql initial_data.sql

step 5 "启动应用程序"
( cd "$ROOT"; RUST_LOG=soulauth=warn exec ./target/debug/soulauth ) > "$WORK/app.log" 2>&1 &
AP_PID=$!; disown $AP_PID
# ⚠ **这里曾是 `seq 30`(= 15 秒),而它不够。**(2026-10-07)
#
# 启动耗时几乎全花在一件事上:没有配 `OIDC_RSA_PRIVATE_KEY_PEM` / `_PATH` 时
# 进程**现生成一枚临时 RSA 密钥**(启动日志里那条 warn 就是它)。
# 放开 `RUST_LOG=debug` 逐行量过,整条启动链上只有这一处 ≥1 秒,其余全在亚秒级。
#
# 而 RSA 生成是**找素数**,耗时天然有方差。本机同一个 debug 二进制连跑 6 次,
# 「Server listening」的耗时:
#
#     6.05s · 8.83s · 5.73s · 7.59s · 5.13s · 6.64s      中位 ~6.3s,跨度 1.7 倍
#
# 本机中位就 6.3 秒,CI runner 的 CPU 更弱 —— 15 秒的预算正好压在边缘上,
# 于是它**不是必然失败,而是间歇失败**;而间歇失败最后一定被当成「又抖了一下」。
#
# ▎对照同一轮 CI 里**通过**的 `integration.sh`:它的 `wait_for` 是
#   `n < 40`(= 20 秒),且判据是 `http_code != "000"`(任何 HTTP 响应都算就绪)。
#   本脚本两个轴都更严(15 秒 + `-sSf` 只认 2xx)—— 差别只在耐心,不在被测内容。
#
# 所以这里给到 60 秒。它不改变本脚本证明的任何事:
# 「照文档能不能从零部署到拿到一个可用的管理员」与启动快不快无关。
# ⚠ 不要改成预置一枚持久密钥来「加速」—— 那会让脚本偏离 DEPLOYMENT.md §3 的步骤,
#   而本脚本存在的全部意义就是照那份文档走。
for i in $(seq 120); do curl -sSf -o /dev/null --max-time 2 "http://127.0.0.1:${AP}/health" 2>/dev/null && break; sleep 0.5; done

step 6 "验证部署 curl /health"
H=$(curl -sSf --max-time 5 "http://127.0.0.1:${AP}/health" 2>/dev/null)
[ -n "$H" ] && ok "$H" || { bad "无响应: $(tail -3 "$WORK/app.log")"; exit 1; }

step "7①" "注册第一个管理员"
C=$(curl -sS --max-time 10 -o "$WORK/r" -w '%{http_code}' -X POST "http://127.0.0.1:${AP}/api/auth/register" \
   -H "Content-Type: application/json" \
   -d '{"email":"admin@your-domain.com","username":"admin","password":"CorrectHorse42!"}' 2>/dev/null)
[ "$C" = 200 ] && ok "注册成功" || bad "返回 $C: $(head -c 120 "$WORK/r")"

step "7②" "授予 admin 角色"
curl -sS --max-time 10 -u "$DATABASE_USER:$DATABASE_PASS" \
  -H "surreal-ns: $DATABASE_NAMESPACE" -H "surreal-db: $DATABASE_NAME" \
  --data "LET \$a = (SELECT VALUE subject_id FROM user WHERE email = 'admin@your-domain.com')[0];
          CREATE user_role CONTENT { user_id: \$a, role_id: role:admin,
            assigned_at: 0, assigned_by: actor_identity:system };" \
  "http://$DATABASE_URL/sql" > "$WORK/g" 2>&1
python3 -c "
import json
d=json.load(open('$WORK/g'))
errs=[x for x in d if x.get('status')!='OK']
print('  '+('\033[32m✓ 授予成功\033[0m' if not errs else '\033[31m✗ '+str(errs[0].get('result'))[:100]+'\033[0m'))" || bad "解析失败"

step "7③④" "重新登录并确认 is_admin"
TOK=$(curl -sS --max-time 10 -X POST "http://127.0.0.1:${AP}/api/auth/login" -H "Content-Type: application/json" \
   -d '{"email":"admin@your-domain.com","password":"CorrectHorse42!"}' 2>/dev/null \
   | python3 -c "import json,sys;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
if [ -z "$TOK" ]; then bad "登录拿不到令牌"; else
  IS=$(curl -sS --max-time 10 "http://127.0.0.1:${AP}/api/auth/me" -H "Authorization: Bearer $TOK" 2>/dev/null \
     | python3 -c "import json,sys;print(json.load(sys.stdin).get('is_admin'))" 2>/dev/null)
  [ "$IS" = "True" ] && ok "is_admin = true —— 部署完成且可用" || bad "is_admin = $IS"
fi

printf '\n\033[1m照修订后文档执行的失败步骤数: %s\033[0m\n' "$FAIL"
