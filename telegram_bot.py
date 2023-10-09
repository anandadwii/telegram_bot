import time
import subprocess
import re
import telegram as tg
import asyncio
import sys

from telegram.ext import Application


async def send_telegram_alert(bot_token, bot_chatID, message):
    bot = tg.Bot(token=bot_token)
    # return await bot.sendMessage(chat_id=bot_chatID, text=message)
    await bot.send_message(connect_timeout=20, chat_id=bot_chatID, text=message)


def ip_check(log):
    ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', log)
    if ip_match:
        return ip_match.group(0)
    else:
        return "IP Not Found"


# Inisialisasi dictionary untuk melacak serangan yang telah terdeteksi
detected_attacks = {
    "SQL Injection": False,
    "Command Injection": False,
    "XSS": False
}

bot_token = "6250732185:AAENk18TZSe3W47v4dQ_P9jOVIXdHRX6EdQ"
bot_chatID = "1041111909"

global_timestamp = None
while True:
    # Baca log kesalahan Apache
    log_data = subprocess.check_output(['tail', '/var/log/apache2/error.log']).decode('utf-8')
    timestamp_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    timestamp_match = re.search(timestamp_pattern, log_data)
    timestamp_log_data = ''
    print('timestamp_log_data start')
    if timestamp_match:
        timestamp_log_data = timestamp_match.group(1)
        print(f'masuk if match{timestamp_log_data}')

    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    print('outside if \n')
    print(f'global_timestamp = {global_timestamp} | timestamp log data = {timestamp_log_data}')
    if global_timestamp is None or global_timestamp != timestamp_log_data:
        print('masuk try')
        try:
            print(f'global_timestamp = {global_timestamp} | timestamp log data = {timestamp_log_data}')
            # Identifikasi serangan SQL Injection
            if "SQL syntax error" in log_data and not detected_attacks["SQL Injection"]:

                # Temukan alamat IP yang terkait dengan serangan (contoh: mencari format XXX.XXX.XXX.XXX)
                detected_ip = ip_check(log_data)

                # Kirim pemberitahuan Telegram tentang serangan
                message = f"Deteksi SQL Injection pada {current_time} dari IP {detected_ip}"
                print(message)
                try:
                    asyncio.run(send_telegram_alert(bot_token, bot_chatID, message))
                    # Kirim ke database disini

                except Exception as e:
                    print(e)

                # Tandai bahwa serangan SQL Injection telah terdeteksi
                detected_attacks["SQL Injection"] = True

            # Identifikasi serangan Command Injection
            if "Command injection" in log_data and not detected_attacks["Command Injection"]:
                detected_ip = ip_check(log_data)
                message = f"Deteksi Command Injection pada {current_time} dari IP {detected_ip}"
                print(message)
                try:
                    asyncio.run(send_telegram_alert(bot_token, bot_chatID, message))
                except Exception as e:
                    print(e)
                # Tandi bahwa serangan Command Injection telah terdeteksi
                detected_attacks["Command Injection"] = True

            # Identifikasi serangan XSS
            if "XSS attack" in log_data and not detected_attacks["XSS"]:
                detected_ip = ip_check(log_data)
                message = f"Deteksi XSS pada {current_time} dari IP {detected_ip}"
                print(message)
                try:
                    asyncio.run(send_telegram_alert(bot_token, bot_chatID, message))
                except Exception as e:
                    print(e)
                # Tandai bahwa serangan XSS telah terdeteksi
                detected_attacks["XSS"] = True

            # Tunggu sebentar sebelum membaca log lagi
            time.sleep(30)  # Baca log setiap 60 detik

            # Setelah semua deteksi selesai, reset variabel detected_attacks
            detected_attacks = {
                "SQL Injection": False,
                "Command Injection": False,
                "XSS": False
            }
            global_timestamp = timestamp_log_data
        except:
            print("Cannot retrieve data in error.log")

    else:
        time.sleep(10)
