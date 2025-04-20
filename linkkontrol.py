import requests
import socket
from urllib.parse import urlparse
import whois

def analyze_url(url):
    result = {}

    # 1. Geçerli URL mi?
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = "http://" + url
            parsed_url = urlparse(url)
        result["Alan Adı"] = parsed_url.netloc
    except Exception as e:
        return {"Hata": "Geçersiz URL"}

    # 2. IP adresi al
    try:
        ip = socket.gethostbyname(parsed_url.netloc)
        result["IP Adresi"] = ip
    except:
        result["IP Adresi"] = "Alınamadı"

    # 3. WHOIS bilgisi
    try:
        w = whois.whois(parsed_url.netloc)
        result["Kayıtlı mı"] = bool(w.domain_name)
        result["Kayıt Tarihi"] = str(w.creation_date)
        result["Kayıt Eden"] = str(w.registrar)
    except:
        result["Kayıtlı mı"] = "Bilinmiyor"

    # 4. Kısaltılmış link mi?
    if parsed_url.netloc in ["bit.ly", "t.co", "tinyurl.com", "goo.gl"]:
        result["Kısaltılmış URL"] = "Evet"
    else:
        result["Kısaltılmış URL"] = "Hayır"

    # 5. Güvenlik skoru (örnek mantık)
    score = 100
    if result["Kısaltılmış URL"] == "Evet":
        score -= 30
    if not result["Kayıtlı mı"]:
        score -= 40
    result["Güvenlik Skoru"] = f"{max(score, 0)} / 100"

    return result

# Test
if __name__ == "__main__":
    url = input("Kontrol etmek istediğiniz URL: ")
    analiz = analyze_url(url)
    for k, v in analiz.items():
        print(f"{k}: {v}")
