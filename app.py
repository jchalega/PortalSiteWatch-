
import os
import hashlib
import socket
import ipaddress
import threading
import difflib
import re

from datetime import datetime
from urllib.parse import urlparse

import requests

from flask import Flask, render_template, request, redirect, url_for

from apscheduler.schedulers.background import BackgroundScheduler


app = Flask(__name__)

MAX_CONTENT_SIZE = 2 * 1024 * 1024
REQUEST_TIMEOUT = 10

DEMO_LOCAL = os.getenv("MONITOR_DEMO_LOCAL", "0") == "1"


monitoramento = {
    "url": "",
    "baseline": None,
    "conteudo_baseline": None,
    "ultimo_hash": None,
    "status": "AGUARDANDO",
    "mensagem": "Informe uma URL para iniciar o monitoramento.",
    "ultimo_check": None,
    "alerta_enviado": False
}

lock = threading.Lock()


def validar_url(url):

    try:

        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False, "Utilize uma URL iniciada com http:// ou https://."

        if not parsed.hostname:
            return False, "URL inválida."

        if parsed.username or parsed.password:
            return False, "URLs com credenciais não são permitidas."

        hostname = parsed.hostname

        if DEMO_LOCAL and hostname.lower() in (
            "localhost",
            "127.0.0.1",
            "::1"
        ):
            return True, "URL local autorizada para demonstração."

        enderecos = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM
        )

        for endereco in enderecos:

            ip = ipaddress.ip_address(endereco[4][0])

            if not ip.is_global:
                return False, "Endereço local ou privado não permitido."

        return True, "URL válida."

    except Exception:
        return False, "Não foi possível validar essa URL."


def gerar_hash(conteudo):

    return hashlib.sha256(conteudo).hexdigest()


def normalizar_html(conteudo):

    html = conteudo.decode("utf-8", errors="replace")

    def normalizar_input(match):

        tag = match.group(0)

        campo_authenticator = re.search(
            r'\bname\s*=\s*(["\'])_authenticator\1',
            tag,
            flags=re.IGNORECASE
        )

        if campo_authenticator:

            tag = re.sub(
                r'(\bvalue\s*=\s*)(["\']).*?\2',
                lambda valor: (
                    valor.group(1)
                    + valor.group(2)
                    + "TOKEN_VARIAVEL"
                    + valor.group(2)
                ),
                tag,
                count=1,
                flags=re.IGNORECASE
            )

        return tag

    html = re.sub(
        r'<input\b[^>]*>',
        normalizar_input,
        html,
        flags=re.IGNORECASE
    )

    return html.encode("utf-8")


def enviar_alerta_telegram(url, baseline, hash_atual):

    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        print("Telegram não configurado. Alerta registrado no sistema.")
        return False

    mensagem = (
        "🚨 ALERTA DE INTEGRIDADE!\n\n"
        "Possível alteração não autorizada detectada.\n\n"
        f"URL: {url}\n"
        f"Baseline: {baseline}\n"
        f"Hash atual: {hash_atual}"
    )

    try:

        endereco_api = (
            f"https://api.telegram.org/bot{token}/sendMessage"
        )

        resposta = requests.post(
            endereco_api,
            data={
                "chat_id": chat_id,
                "text": mensagem
            },
            timeout=10
        )

        resposta.raise_for_status()

        print("Alerta enviado pelo Telegram!")

        return True

    except requests.RequestException as erro:

        print(f"Erro ao enviar alerta: {erro}")

        return False


def verificar_integridade():

    with lock:

        url = monitoramento["url"]

        if not url:
            return

        try:

            print(f"Verificando integridade: {url}")

            with requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                headers={
                    "User-Agent": "MonitorIntegridade/1.0"
                },
                allow_redirects=False,
                stream=True
            ) as resposta:

                if 300 <= resposta.status_code < 400:
                    raise ValueError(
                        "A página retornou um redirecionamento."
                    )

                resposta.raise_for_status()

                partes = []
                tamanho_total = 0

                for parte in resposta.iter_content(chunk_size=8192):

                    if not parte:
                        continue

                    tamanho_total += len(parte)

                    if tamanho_total > MAX_CONTENT_SIZE:
                        raise ValueError(
                            "A página ultrapassou o limite de 2 MB."
                        )

                    partes.append(parte)

                conteudo = b"".join(partes)

                print(
                    "TAMANHO DO CONTEÚDO:",
                    len(conteudo),
                    "bytes"
                )

            conteudo_normalizado = normalizar_html(conteudo)

            hash_atual = gerar_hash(conteudo_normalizado)

            print("HASH ATUAL:", hash_atual)
            print("HASH BASELINE:", monitoramento["baseline"])

            monitoramento["ultimo_hash"] = hash_atual

            monitoramento["ultimo_check"] = (
                datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            )

            if monitoramento["baseline"] is None:

                monitoramento["baseline"] = hash_atual

                monitoramento["conteudo_baseline"] = (
                    conteudo_normalizado
                )

                monitoramento["status"] = "SEGURO"

                monitoramento["mensagem"] = (
                    "Baseline definido! Monitoramento iniciado."
                )

                print("Baseline criado com sucesso!")

            elif hash_atual == monitoramento["baseline"]:

                monitoramento["status"] = "SEGURO"

                monitoramento["mensagem"] = (
                    "Nenhuma alteração relevante no conteúdo "
                    "foi detectada."
                )

                monitoramento["alerta_enviado"] = False

                print("Integridade preservada!")

            else:

                monitoramento["status"] = "ALERTA"

                monitoramento["mensagem"] = (
                    "Alteração no conteúdo detectada! "
                    "Investigue a possível ocorrência de defacement."
                )

                print("ALERTA: Divergência de hash detectada!")

                original = (
                    monitoramento["conteudo_baseline"].decode(
                        "utf-8",
                        errors="replace"
                    )
                )

                atual = conteudo_normalizado.decode(
                    "utf-8",
                    errors="replace"
                )

                diferencas = list(difflib.unified_diff(
                    original.splitlines(),
                    atual.splitlines(),
                    fromfile="Baseline",
                    tofile="Conteúdo atual",
                    lineterm=""
                ))

                print("\n--- DIFERENÇAS ENCONTRADAS ---")

                if diferencas:

                    for linha in diferencas[:30]:
                        print(linha)

                else:

                    print("Nenhuma diferença textual encontrada.")

                print("--- FIM DAS DIFERENÇAS ---")

                if not monitoramento["alerta_enviado"]:

                    enviar_alerta_telegram(
                        url,
                        monitoramento["baseline"],
                        hash_atual
                    )

                    monitoramento["alerta_enviado"] = True

        except Exception as erro:

            monitoramento["status"] = "ERRO"

            monitoramento["mensagem"] = (
                f"Não foi possível verificar a página: {erro}"
            )

            print(f"Erro no monitoramento: {erro}")


scheduler = BackgroundScheduler(
    daemon=True,
    timezone="America/Campo_Grande"
)

scheduler.add_job(
    func=verificar_integridade,
    trigger="interval",
    seconds=30,
    id="monitoramento_integridade",
    max_instances=1,
    coalesce=True
)


@app.route("/", methods=["GET", "POST"])
def index():

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        valida, mensagem = validar_url(url)

        if not valida:

            with lock:
                monitoramento["mensagem"] = mensagem
                monitoramento["status"] = "ERRO"

            return redirect(url_for("index"))

        with lock:

            if url != monitoramento["url"]:

                monitoramento.update({
                    "url": url,
                    "baseline": None,
                    "conteudo_baseline": None,
                    "ultimo_hash": None,
                    "status": "AGUARDANDO",
                    "mensagem": "Estabelecendo Baseline...",
                    "ultimo_check": None,
                    "alerta_enviado": False
                })

        verificar_integridade()

        return redirect(url_for("index"))

    with lock:
        dados = monitoramento.copy()

    return render_template("index.html", dados=dados)


if __name__ == "__main__":

    scheduler.start()

    print("========================================")
    print(" MONITOR DE INTEGRIDADE INICIADO")
    print(" Verificação automática: 30 segundos")
    print(" Acesse: http://127.0.0.1:5000")
    print("========================================")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False
    )