# ThreadVeil


**Description :**

An advanced Windows tool that uses RC4 encryption to inject shellcode via the Remote Thread Hijacking technique, incorporating API obfuscation to obscure IAT visibility and evade detection by AVs


# Features

**[+] Obfuscation Techniques:** Employs Rc4 encryption to avoid signature-based detection. & incorporated API obfuscation 

**[+] Remote Thread Hijacking** Technique where an external process takes control of a suspended thread in a target process to execute malicious code

**[+] Anti-Debugging/Anti-Sandboxing**: Validates environnement first , won't execute if there is no internet or if specific processes are running in the background.


# Getting Started

**Installation**


1. Clone the repository:
```
git clone https://github.com/Cyb3rV1c/ThreadVeil
```


# Usage

1. Add your Rc4 encrypted shellcode in ThreadVeil.cpp 

2. Specify Secret Key for Decryption

3. Compile & Run.


# Example Output

**Execution** 

![Screenshot 2024-11-14 at 2 10 35 PM](https://github.com/user-attachments/assets/0a30f138-8503-4a00-b391-9cfe93b78d5e)

<img width="548" alt="Screenshot 2024-11-15 at 4 19 28 PM" src="https://github.com/user-attachments/assets/face303f-6d6c-44a9-ac4a-4767d67d71eb">



![Screenshot 2024-11-14 at 2 33 25 PM](https://github.com/user-attachments/assets/a2d8804b-7022-481f-a53b-66426be29381)




# Disclaimer
**This project is intended for educational and research purposes only.**

The code provided in this repository is designed to help individuals understand and improve their knowledge of cybersecurity, ethical hacking, and malware analysis techniques. It must not be used for malicious purposes or in any environment where you do not have explicit permission from the owner.
