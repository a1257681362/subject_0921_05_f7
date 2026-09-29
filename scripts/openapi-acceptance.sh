#!/bin/sh
# 对外开放加工单查询（/open/api/**）HMAC 签名鉴权——验收当天一键自检。
#
# 六个用例（任一不过即非零退出）：
#   1) 正常签名按单号查询        期望 HTTP 200 / code=OK
#   2) query 参数乱序发送        期望 HTTP 200 / code=OK（服务端 canonical 重排）
#   3) 时间戳早于 16 分钟        期望 HTTP 401 / code=SIGN_EXPIRED
#   4) 同一 nonce 连发两次       首次 OK，第二次 401 / code=NONCE_DUPLICATED
#   5) 签名错误                  期望 HTTP 401 / code=SIGN_INVALID
#   6) 缺签名头                  期望 HTTP 401 / code=SIGN_INVALID
#
# 用法:
#   APP_ID=demo-partner APP_SECRET=dev-only-please-override sh scripts/openapi-acceptance.sh
# 可选环境变量:
#   BASE_URL   服务地址，默认 http://localhost:8080
#   ADMIN_USER/ADMIN_PASS  内部建档用 Basic 账号，默认 bootstrap/bootstrap（仅造验收数据）
#
# 依赖: curl、openssl。验收当天跑两轮：第一轮现场看结果，第二轮同命令录屏。

set -u

BASE_URL="${BASE_URL:-http://localhost:8080}"
APP_ID="${APP_ID:?请先 export APP_ID=接入方appId}"
APP_SECRET="${APP_SECRET:?请先 export APP_SECRET=接入方密钥}"
ADMIN_USER="${ADMIN_USER:-bootstrap}"
ADMIN_PASS="${ADMIN_PASS:-bootstrap}"

PASS=0
FAIL=0

# 从 "响应体\nHTTP状态" 末行取状态码
http_code() { printf '%s' "$1" | tail -n 1; }
# 取响应体（去掉末行状态码），粗匹配 JSON 字段（不依赖 jq）
body() { printf '%s' "$1" | sed '$d'; }
body_has() { case "$(body "$1")" in *"\"code\":\"$2\""*) return 0;; *) return 1;; esac; }

report() {
    if [ "$1" = "0" ]; then
        echo "PASS  $2"
        PASS=$((PASS + 1))
    else
        echo "FAIL  $2（实际 HTTP=$(http_code "$3") body=$(body "$3" | head -c 200)）"
        FAIL=$((FAIL + 1))
    fi
}

# sign_request METHOD URI CANONICAL_QUERY TS NONCE -> 输出签名（hex 小写）
# 待签名串: METHOD\nURI\nTS\nNONCE\nCANONICAL（注意末段为空时串尾仍有换行，直接管道喂 openssl）
sign() {
    _method="$1"; _uri="$2"; _canon="$3"; _ts="$4"; _nonce="$5"
    # 顺序固定 METHOD\nURI\nTS\nNONCE\nCANON（canon 为空时串尾保留最后一个换行）
    printf '%s\n%s\n%s\n%s\n%s' "$_method" "$_uri" "$_ts" "$_nonce" "$_canon" \
        | openssl dgst -sha256 -hmac "$APP_SECRET" | awk '{print $NF}'
}

# signed_get URI CANONICAL [SENT_QUERY] [TS] [NONCE]
signed_get() {
    _uri="$1"; _canon="$2"; _sent="${3:-$2}"; _ts="${4:-$(date +%s%3N 2>/dev/null || echo $(( $(date +%s) * 1000 )) )}"; _nonce="${5:-nonce-$(date +%s)-$$-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')}"
    _sig="$(sign GET "$_uri" "$_canon" "$_ts" "$_nonce")"
    _url="$BASE_URL$_uri"
    [ -n "$_sent" ] && _url="$_url?$_sent"
    curl -sS -w '\n%{http_code}' "$_url" \
        -H "X-Access-App: $APP_ID" \
        -H "X-Timestamp: ${_ts}" \
        -H "X-Nonce: ${_nonce}" \
        -H "X-Signature: ${_sig}"
}

echo "== 对 $BASE_URL 跑对外接口鉴权验收（appId=$APP_ID）=="

# ---- 造验收数据：内部接口建档（Basic），单号本进程唯一 ----
STAMP="$(date +%s)-$$"
LENS_CODE="L-ACC-$STAMP"
ORDER_NO="O-ACC-$STAMP"
LENS_RESP="$(curl -sS -u "$ADMIN_USER:$ADMIN_PASS" -X POST "$BASE_URL/api/lens" \
    -H 'Content-Type: application/json' \
    -H "X-Operator-Id: 9001" -H "X-Request-No: acc-lens-$STAMP" \
    -d "{\"lensCode\":\"$LENS_CODE\",\"lensName\":\"验收片\",\"lensType\":\"单光\",\"price\":399.00}")"
# 不依赖 jq：取首个 "id":数字
LENS_ID="$(printf '%s' "$LENS_RESP" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' | head -1)"
if [ -z "$LENS_ID" ]; then
    echo "建档镜片失败，无法继续：$LENS_RESP" >&2
    exit 2
fi
curl -sS -o /dev/null -u "$ADMIN_USER:$ADMIN_PASS" -X POST "$BASE_URL/api/orders" \
    -H 'Content-Type: application/json' \
    -H "X-Operator-Id: 9001" -H "X-Request-No: acc-order-$STAMP" \
    -d "{\"orderNo\":\"$ORDER_NO\",\"lensId\":$LENS_ID,\"storeCode\":\"S01\",\"customerName\":\"验收客户\",\"prescriptions\":[{\"eye\":\"L\",\"sphere\":-1.00},{\"eye\":\"R\",\"sphere\":-1.00}]}"

# ---- 用例 1：正常签名按单号查询 ----
R="$(signed_get "/open/api/orders/by-no/$ORDER_NO" "")"
[ "$(http_code "$R")" = "200" ] && body_has "$R" "OK" && body "$R" | grep -q "$ORDER_NO"
report $? "1 正常签名按单号查询 -> 200/OK" "$R"

# ---- 用例 2：参数乱序发送，签名按 canonical（字典序）计算 ----
R="$(signed_get "/open/api/orders" "status=CREATED&storeCode=S01" "storeCode=S01&status=CREATED")"
[ "$(http_code "$R")" = "200" ] && body_has "$R" "OK"
report $? "2 query 参数乱序发送（canonical 重排验签）-> 200/OK" "$R"

# ---- 用例 3：时间窗外（早 16 分钟）----
OLD_TS=$(( $(date +%s) * 1000 - 16 * 60 * 1000 ))
R="$(signed_get "/open/api/orders/by-no/$ORDER_NO" "" "" "$OLD_TS")"
[ "$(http_code "$R")" = "401" ] && body_has "$R" "SIGN_EXPIRED"
report $? "3 时间戳早于窗口 16 分钟 -> 401/SIGN_EXPIRED" "$R"

# ---- 用例 4：nonce 重放 ----
TS="$(date +%s%3N 2>/dev/null || echo $(( $(date +%s) * 1000 )) )"
NONCE="replay-$(date +%s)-$$"
R1="$(signed_get "/open/api/orders/by-no/$ORDER_NO" "" "" "$TS" "$NONCE")"
R2="$(signed_get "/open/api/orders/by-no/$ORDER_NO" "" "" "$TS" "$NONCE")"
if [ "$(http_code "$R1")" = "200" ] && body_has "$R1" "OK" \
   && [ "$(http_code "$R2")" = "401" ] && body_has "$R2" "NONCE_DUPLICATED"; then
    OK4=0
else
    OK4=1
fi
report $OK4 "4 同一 nonce 连发两次 -> 首次 OK，第二次 401/NONCE_DUPLICATED" "$R2"

# ---- 用例 5：签名错误（其余头合法）----
TS="$(date +%s%3N 2>/dev/null || echo $(( $(date +%s) * 1000 )) )"
NONCE="badsig-$(date +%s)-$$"
R="$(curl -sS -w '\n%{http_code}' "$BASE_URL/open/api/orders/by-no/$ORDER_NO" \
        -H "X-Access-App: $APP_ID" -H "X-Timestamp: $TS" -H "X-Nonce: $NONCE" \
        -H 'X-Signature: 00deadbeef')"
[ "$(http_code "$R")" = "401" ] && body_has "$R" "SIGN_INVALID"
report $? "5 签名错误 -> 401/SIGN_INVALID" "$R"

# ---- 用例 6：缺签名头 ----
R="$(curl -sS -w '\n%{http_code}' "$BASE_URL/open/api/orders/by-no/$ORDER_NO" \
        -H "X-Access-App: $APP_ID" -H "X-Timestamp: $(date +%s)000")"
[ "$(http_code "$R")" = "401" ] && body_has "$R" "SIGN_INVALID"
report $? "6 缺签名头 -> 401/SIGN_INVALID" "$R"

echo "== 结果：PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" -eq 0 ]
