import smtplib
from email.mime.text import MIMEText

def send_alert(message):
    sender = "lobjois.even@gmail.com"
    password = "Loucaclara27062015+n"

    msg = MIMEText(message)
    msg["Subject"] = "ALERTE RESEAU"
    msg["From"] = sender
    msg["To"] = sender

    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(sender, password)
        server.sendmail(sender, sender, msg.as_string())
        server.quit()
        print("Mail envoyé")
    except Exception as e:
        print("Erreur mail:", e)
