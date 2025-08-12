# Suporte N2 - Windows Toolkit (Flet)

Aplicação em **Python + Flet** para execução rápida de comandos comuns no Windows, voltada para analistas de suporte N2.

## 📌 Funcionalidades

- **Rede:**
  - `ipconfig /all`
  - Ping (4 pacotes)
  - Tracert
  - Nslookup
  - Teste de porta TCP (`Test-NetConnection`)
- **Sistema:**
  - Informações do sistema (`systeminfo`)
  - Uptime via CIM (funciona no PowerShell 5.1+)
  - Última inicialização via WMIC

## 🖥️ Requisitos

- Windows 10 ou superior
- Python 3.9+
- [Flet](https://flet.dev) instalado:
  ```bash
  pip install flet
  ```
- PowerShell disponível no sistema (padrão no Windows)

## ▶️ Como executar

1. Clone este repositório:
   ```bash
   git clone https://github.com/seuusuario/suporte-n2-toolkit.git
   cd suporte-n2-toolkit
   ```
2. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
3. Execute o app:
   ```bash
   python app.py
   ```

## 📂 Estrutura do projeto

```
├── TelaPrincipal.py               # Código principal
├── requirements.txt     # Dependências
└── README.md            # Este arquivo
```

## ⚠️ Observações

- Alguns comandos exigem **permissões de administrador**.
- O app é voltado exclusivamente para **Windows**.

## 📜 Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo LICENSE para mais detalhes.

