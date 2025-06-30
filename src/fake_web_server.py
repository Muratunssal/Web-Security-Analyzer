from flask import Flask, render_template_string

app = Flask(__name__)

html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sahte Giriş</title>
</head>
<body>
    <h2>Giriş Yap</h2>
    <form action="#" method="post">
        <input type="text" placeholder="Kullanıcı Adı" required><br><br>
        <input type="password" placeholder="Şifre" required><br><br>
        <input type="submit" value="Giriş">
    </form>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(html)

if __name__ == "__main__":
    print("[*] Sahte web sunucusu çalışıyor: http://0.0.0.0:80")
    app.run(host="0.0.0.0", port=80)
