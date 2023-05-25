import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication 


def send_mail(file_path, data):
    # 이메일 정보
    email_sender = 'zentest@naver.com'
    email_receiver = email_sender
    email_subject = file_path
    email_body = '점검 결과입니다.\n\n'
    email_body += data

    # 이메일 생성
    message = MIMEMultipart()
    message['From'] = email_sender
    message['To'] = email_receiver
    message['Subject'] = email_subject

    # 이메일 본문 추가
    message.attach(MIMEText(email_body, 'html'))

    # 첨부 파일 추가
#    etc_file_path = file_path
#    with open(etc_file_path, 'rb') as f : 
#        etc_part = MIMEApplication( f.read() )
#        etc_part.add_header('Content-Disposition','attachment', filename=etc_file_path)
#        message.attach(etc_part)

    # SMTP 서버 연결 및 로그인
    smtp_username = 'zentest'
    smtp_password = 'Qweasd123@'
    smtp_connection = smtplib.SMTP('smtp.naver.com', 587)
    smtp_connection.starttls()
    smtp_connection.login(smtp_username, smtp_password)

    # 이메일 전송
    smtp_connection.sendmail(email_sender, email_receiver, message.as_string())

    # SMTP 서버 연결 종료
    smtp_connection.quit()
