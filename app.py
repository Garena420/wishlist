import change_wishlist_pb2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import wishlist_pb2
import base64
import json
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

key = b'Yg&tc%DEuh6%Zc^8'
iv = b'6oyZDr22E3ychjM%'

def encrypt_aes(key: bytes, iv: bytes, plaintext: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext.hex()

def jwt(uid, password):
    api = f"https://www.jwtinfo.freefireinfo.site/api/{uid}/{password}"
    response = requests.get(api)
    if response.status_code != 200:
        raise Exception("Failed to retrieve JWT: " + response.text)
    return json.loads(response.text)

def payload(item_id, mode, hex_type):
    wishlist = change_wishlist_pb2.Wishlist()
    wishlist.value.item_id = item_id
    wishlist.value.garena_420 = 2265067095
    binary_data = wishlist.SerializeToString()
    hex_data = binary_data.hex()
    if mode == "add":
        if hex_type == "1":
        	prefix_to_remove = "0a0b08"
        else:
        	prefix_to_remove = "0a0c08"
    else:
        if hex_type == "1":
        	prefix_to_remove = "0a0b08"
        else:
        	prefix_to_remove = "0a0c08"
        	
    truncate_pattern = "10d7dc88b808"
    if hex_data.startswith(prefix_to_remove):
        hex_data = hex_data[len(prefix_to_remove):]
    truncate_index = hex_data.find(truncate_pattern)
    if truncate_index != -1:
        hex_data = hex_data[:truncate_index]
    if mode == "add":
        if hex_type == "1":
        	payload = f"0a04{hex_data}12001a064d616c6c5632"
        else:
        	payload = f"0a05{hex_data}12001a064d616c6c5632"
    else:
        if hex_type == "1":
        	payload = f"0a001204{hex_data}22064d616c6c5632"
        else:
        	payload = f"0a001205{hex_data}22064d616c6c5632"
        	
    plaintext = bytes.fromhex(payload)
    encrypted = encrypt_aes(key, iv, plaintext)
    return encrypted

def make_request(region, encrypted, token):
    if region == "IND":
        url = "https://client.ind.freefiremobile.com/ChangeWishListItem"
    elif region == "BR":
        url = "https://client.us.freefiremobile.com/ChangeWishListItem"
    else:
        url = "https://clientbp.ggblueshark.com/ChangeWishListItem"
    body = bytes.fromhex(encrypted)
    
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB46"
    }
    
    response = requests.post(url, data=body, headers=headers)
    if response.status_code != 200:
        raise Exception("Request failed from official api" + response.text)
    return response

def hex_to_binary(hex_string):
    return bytes.fromhex(hex_string)

def decode_protobuf(binary_data):
    items = wishlist_pb2.Items()
    items.ParseFromString(binary_data)
    return items

def items_to_json(items):
    items_json = {
        "items": []
    }
    for item in items.items:
        items_json["items"].append({
            "itemId": item.itemId,
            "releaseTime": str(item.releaseTime)
        })
    return items_json

def decode_protobuf_to_json(binary_data: bytes) -> str:
    binary_data = hex_to_binary(binary_data)
    decoded_items = decode_protobuf(binary_data)
    items_json = items_to_json(decoded_items)
    return (json.dumps(items_json, indent=2))
    
def respons(item_id, uid, password, mode, hex_type):
    encrypted_payload = payload(item_id, mode, hex_type)
    data = jwt(uid, password)
    token = data.get("token")
    if not token:
        raise Exception("Token not found in response")
    decoded_payload = data.get('decoded_payload', {})
    region = decoded_payload.get('lock_region')
    res = make_request(region, encrypted_payload, token)
    if isinstance(res, dict) and 'error' in res:
        return jsonify(res), 500

    binary_data = res.content.hex()
    json_output = decode_protobuf_to_json(binary_data)
    return json_output

@app.route("/add_item", methods=["GET"])
def add_item():
    item_id = request.args.get('item_id')
    uid = request.args.get('uid')
    password = request.args.get('password')
    mode = "add"
    item_id = int(item_id)
    item_id_str = str(item_id)
    if item_id_str.startswith(("2030", "2040", "2050", "2110")):
    	hex_type = "1"
    else:
    	hex_type = "2"
    las = respons(item_id, uid, password, mode, hex_type)
    return las, 200
        
@app.route("/remove_item", methods=["GET"])
def remove_item():
    item_id = request.args.get('item_id')
    uid = request.args.get('uid')
    password = request.args.get('password')
    mode = "remove"
    item_id = int(item_id)
    item_id_str = str(item_id)
    if item_id_str.startswith(("2030", "2040", "2050", "2110")):
    	hex_type = "1"
    else:
    	hex_type = "2"
    las = respons(item_id, uid, password, mode, hex_type)
    return las, 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=True)
