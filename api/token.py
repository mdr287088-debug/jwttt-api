import json
import base64
import asyncio
import httpx
from Crypto.Cipher import AES
from flask import Flask, request, jsonify
from google.protobuf import json_format
from proto import FreeFire_pb2

app = Flask(__name__)

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
RELEASEVERSION = "OB52"


def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))


async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = f"{account}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"

    headers = {
        'User-Agent': USERAGENT,
        'Content-Type': "application/x-www-form-urlencoded"
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")


async def create_jwt(uid: str, password: str):
    account = f"uid={uid}&password={password}"
    token_val, open_id = await get_access_token(account)

    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4"
    })

    proto_message = FreeFire_pb2.LoginReq()
    json_format.ParseDict(json.loads(body), proto_message)
    proto_bytes = proto_message.SerializeToString()

    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    url = "https://loginbp.ggblueshark.com/MajorLogin"

    headers = {
        'User-Agent': USERAGENT,
        'Content-Type': "application/octet-stream",
        'ReleaseVersion': RELEASEVERSION
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)

        msg = json.loads(
            json_format.MessageToJson(
                FreeFire_pb2.LoginRes.FromString(resp.content)
            )
        )

        return {
            "token": msg.get("token", "0"),
            "region": msg.get("lockRegion", "0"),
            "server_url": msg.get("serverUrl", "0")
        }


@app.route('/api/token')
def handler():
    uid = request.args.get("uid")
    password = request.args.get("password")

    if not uid or not password:
        return jsonify({"error": "uid and password required"}), 400

    result = asyncio.run(create_jwt(uid, password))
    return jsonify(result)
