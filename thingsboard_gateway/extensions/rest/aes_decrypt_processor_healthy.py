import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from thingsboard_gateway.connectors.converter import Converter
from thingsboard_gateway.gateway.entities.converted_data import ConvertedData
from thingsboard_gateway.gateway.entities.telemetry_entry import TelemetryEntry
from thingsboard_gateway.tb_utility.tb_utility import TBUtility


class AESDecryptConverterHealth(Converter):
    def __init__(self, config,logger):
        self._log = logger
        self.__config = config.get('extension-config')
        self.__key = self.__config.get("key", "")
        self.__iv = self.__config.get("iv", "")#.encode('utf-8')

    def convert(self, config, data):
        device_name = data.get('sensorName')
        device_type = data.get('sensorType')
        converted_data = ConvertedData(device_name, device_type)
        try:
            # REST 数据通常是 JSON 格式，提取加密字段
            encrypted_data = data.get("data", "")  # 根据实际字段名调整

            # 解码 Base64 密文
            ciphertext = base64.b64decode(encrypted_data)

            key_bytes = bytes.fromhex(self.__key)
            iv_bytes = bytes.fromhex(self.__iv)
            # 创建 AES 解密器
            cipher = AES.new(key_bytes, AES.MODE_CBC,iv_bytes )

            # 解密并去除填充
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            decrypted_data = decrypted.decode('utf-8')

            # 解析 JSON 数据
            telemetry_data = json.loads(decrypted_data)
            # 为每个数据点创建TelemetryEntry
            for key, value in telemetry_data.items():
                # 转换为ThingsBoard数据点键
                datapoint_key = TBUtility.convert_key_to_datapoint_key(key, None, {}, self._log)

                # 创建遥测条目
                telemetry_entry = TelemetryEntry({datapoint_key: value})

                # 添加到转换后的数据中
                converted_data.add_to_telemetry(telemetry_entry)

            self._log.debug(f"成功转换数据: {telemetry_data}")
            return converted_data

        except Exception as e:
            self._log.error(f"AES 解密失败: {e}")
            return None