# 🔍 Automated Vulnerability Scanner

## 📖 Introduction

**Automated Vulnerability Scanner** is a powerful cybersecurity tool designed to detect and analyze vulnerabilities in networks and systems using **Nmap**. It provides a **user-friendly web interface**, stores scan history in **SQLite**, and offers **interactive reports** in **JSON, PDF, and graphical visualizations**.

> **Disclaimer:** This tool is intended for **educational and security auditing purposes only**. Unauthorized use against systems you don’t own is strictly prohibited.

⭐ **If you find this project useful, consider starring the repository!**

---

## 🏆 Features

✔ **Automated vulnerability scanning** using `nmap`  
✔ **Stores scan history** in SQLite for easy retrieval  
✔ **Exports scan results** as JSON and PDF reports  
✔ **Interactive web-based UI** powered by Flask & Bootstrap  
✔ **Graphical analysis** of open ports and scan results  
✔ **Optimized scanning** to reduce unnecessary checks  
✔ **Fast and user-friendly experience**  

---

## 🔧 Configuration

Before running the scanner, ensure **Nmap** is installed and accessible from the command line.

| Setting      | Description |
|-------------|-------------|
| `target`    | The IP address or domain to scan |
| `os`        | Identifies the target operating system |
| `ports`     | Scans open ports and running services |
| `vulnerabilities` | Detects potential security vulnerabilities |
| `export`    | Enables JSON and PDF report generation |

---

## ⚒️ Setup Instructions

Follow these steps to install and run the Automated Vulnerability Scanner:

### **1️⃣ Clone the repository**
```bash
git clone https://github.com/OnyxByte/automated-vuln-scanner.git
cd automated-vuln-scanner
```

### **2️⃣ Install dependencies**
```bash
pip install -r requirements.txt
```

### **3️⃣ Run the application**
```bash
python app.py
```

📌 **Now open your browser and navigate to:**
```
http://127.0.0.1:5000/
```

---

## 🛠 Technologies Used

- 🐍 **Python** – Backend processing  
- 🌐 **Flask** – Web framework  
- 🔍 **Nmap** – Security scanning  
- 📊 **SQLite** – Database for storing scan history  
- 🎨 **Bootstrap** – Frontend styling  
- 📈 **Matplotlib** – Graphical data visualization  
- 📄 **ReportLab** – PDF report generation  

---

## 📊 Graphical Insights

The tool includes **data visualization** to help analyze scan results. The generated graphs display:

- **Open ports per scan**
- **Vulnerability distribution**
- **Service versions detected**

Example graph output:  
![Graph Example](https://via.placeholder.com/600x300?text=Graph+Example)

---

## 📡 API Endpoints (Planned Feature)
Future versions may include a REST API for remote scanning capabilities.

---

## 🔮 Future Enhancements
- [ ] API for remote scan execution  
- [ ] Integration with **Shodan** or **VirusTotal**  
- [ ] User authentication for restricted access  
- [ ] Scheduled automated scans  

---

## 🐛 Bug Reports & Feature Requests

Have an issue or suggestion? **Submit it [here](../../issues)** Provide:

- Expected behavior  
- Actual behavior  
- Steps to reproduce  
- Suggested improvements  

---

## 🤝 Contributing

Pull requests are welcome! If you'd like to contribute, please **fork the repository** and submit a pull request.

---

## 📄 License

This project is **MIT licensed** – feel free to use and modify it!

---

## 📜 Closing Notes

If you enjoyed this project, **drop a star!** ⭐  
