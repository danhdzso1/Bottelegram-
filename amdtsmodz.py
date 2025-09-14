import os, sys
import requests
import time, datetime
import asyncio, aiohttp
import base64, json, jwt
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class AddFr:
	def __init__(self):
		pass
	
	
	def fix_hex(self, hex):
		hex = hex.lower().replace(" ", "")
		
		return hex
	
	
	def dec_to_hex(self, decimal):
		decimal = hex(decimal)
		final_result = str(decimal)[2:]
		if len(final_result) == 1:
			final_result = "0" + final_result
			return final_result
		
		else:
			return final_result
	
	
	def encode_varint(self, number):
		if number < 0:
			raise ValueError("Number must be non-negative")
		
		encoded_bytes = []
		
		while True:
			byte = number & 0x7F
			number >>= 7
		
			if number:
				byte |= 0x80
			encoded_bytes.append(byte)
			
			if not number:
				break
		
		return bytes(encoded_bytes)
	
	
	def create_varint_field(self, field_number, value):
		field_header = (field_number << 3) | 0# Varint wire type is 0
		return self.encode_varint(field_header) + self.encode_varint(value)
	
	
	def create_length_delimited_field(self, field_number, value):
		field_header = (field_number << 3) | 2# Length-delimited wire type is 2
		encoded_value = value.encode() if isinstance(value, str) else value
		return self.encode_varint(field_header) + self.encode_varint(len(encoded_value)) + encoded_value
	
	
	def create_protobuf_packet(self, fields):
		packet = bytearray()
		
		for field, value in fields.items():
			if isinstance(value, dict):
				nested_packet = self.create_protobuf_packet(value)
				packet.extend(self.create_length_delimited_field(field, nested_packet))
			
			elif isinstance(value, int):
				packet.extend(self.create_varint_field(field, value))
			
			elif isinstance(value, str) or isinstance(value, bytes):
				packet.extend(self.create_length_delimited_field(field, value))
		
		return packet
	def Encrypt_API(self, plain_text):
		plain_text = bytes.fromhex(plain_text)
		key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
		iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
		cipher = AES.new(key, AES.MODE_CBC, iv)
		cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
		
		return cipher_text.hex()

	def RequestAddingFriend(self, account_id, player_id, token):
		fields = {
			1: int(account_id),
			2: int(player_id),
			3: 3
		}
		
		payload = self.create_protobuf_packet(fields)
		payload = payload.hex()
		payload = self.Encrypt_API(payload)
		payload = bytes.fromhex(payload)
		
		headers = {
			"Expect": "100-continue",
			"Authorization": "Bearer " + token,
			"X-Unity-Version": "2018.4.11f1",
			"X-GA": "v1 1",
			"ReleaseVersion": "OB50",
			"Connection": "Close",
			"Content-Type": "application/x-www-form-urlencoded",
			"Content-Length": str(len(payload)),
			"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 10; RMX1821 Build/QP1A.190711.020)",
			"Host": "clientbp.ggblueshark.com",
			"Accept-Encoding": "gzip"
		}
		
		response = requests.post("https://clientbp.ggblueshark.com/RequestAddingFriend", headers=headers, data=payload)
		
		return response.content