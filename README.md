**Broken Authentication**

By Ramyar Daneshgar 

## **Introduction**

In this lab, I conducted a penetration test against a web application to identify and exploit broken authentication vulnerabilities. My objective was to systematically enumerate users, leverage credential stuffing, manipulate authentication tokens, and escalate privileges to gain administrative access. This writeup follows an offensive security methodology, utilizing enumeration techniques, brute-force attacks, token hijacking, and session manipulation. 


## **Step 1: Enumerating Users**

### **Objective:** Identify valid usernames through response-based enumeration.

User enumeration occurs when an application provides different error messages for invalid usernames versus incorrect passwords. This information disclosure vulnerability allows an attacker to verify valid accounts through systematic queries.

### **Process & Logic:**

1. I navigated to the authentication page and attempted login with random credentials.
2. Using browser DevTools (Ctrl + Shift + E), I analyzed the HTTP responses.
3. I found that incorrect usernames returned an "Unknown user" error, while incorrect passwords for valid users returned "Incorrect password." This difference allowed me to infer valid usernames.
4. To automate this attack, I used `ffuf`, a fast web fuzzer:

```bash
ffuf -w /opt/useful/SecLists/Usernames/xato-net-10-million-usernames.txt \
     -u http://STMIP:STMPO/index.php \
     -X POST -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=FUZZ&password=123" -fr "Unknown user."
```

- `-w`: Specifies the wordlist containing potential usernames.
- `-X POST`: Ensures the request is a POST request.
- `-H`: Sets the request header for proper content type.
- `-d`: Sends form data, fuzzing the `username` field.
- `-fr "Unknown user."`: Filters out responses containing "Unknown user." since that indicates a non-existent username.

This technique successfully revealed valid usernames.

---

## **Step 2: Brute-Forcing Credentials**

### **Objective:** Exploit weak password policies to obtain valid credentials.

Once I identified a valid username, I proceeded with a credential brute-force attack.

### **Process & Logic:**

1. I observed the web application’s password policy, which required at least one uppercase letter, one lowercase letter, and one digit, with a minimum length of 10 characters.
2. I filtered `rockyou.txt` to include only compliant passwords:

```bash
sudo grep '[[:upper:]]' /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt | \
grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > rockyouTrimmed.txt
```

- `grep '[[:upper:]]'`: Filters passwords containing at least one uppercase letter.
- `grep '[[:lower:]]'`: Ensures passwords have lowercase letters.
- `grep '[[:digit:]]'`: Filters passwords with at least one number.
- `grep -E '.{10}'`: Ensures the password length is 10 or more.

3. I executed a brute-force attack using `ffuf`:

```bash
ffuf -w rockyouTrimmed.txt -u http://STMIP:STMPO/index.php \
     -X POST -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=admin&password=FUZZ" -fr "Invalid username or password." -t 60
```

- This systematically tested passwords from my filtered list against the admin account.
- The correct password was identified, granting me access.

---

## **Step 3: Exploiting Weak Password Reset Tokens**

### **Objective:** Exploit short-lived OTP vulnerabilities to take over an account.

The password reset feature used a **4-digit OTP**, which is easily brute-forced.

### **Process & Logic:**

1. I requested a password reset and intercepted the link containing `token=XXXX`.
2. I generated a wordlist of all 4-digit combinations:

```bash
seq -w 0000 9999 > tokens.txt
```

- `seq -w 0000 9999`: Generates numbers from 0000 to 9999, ensuring uniform length.

3. I launched a brute-force attack using `ffuf`:

```bash
ffuf -w tokens.txt -u http://STMIP:STMPO/reset_password.php?token=FUZZ \
     -fr "The provided token is invalid" -t 60
```

- Since there are only 10,000 possible values, brute-forcing is trivial.
- I obtained a valid OTP and reset the admin password.

---

## **Step 4: Authentication Bypass via Insecure Direct Object Reference (IDOR)**

### **Objective:** Exploit IDOR to gain admin access.

IDOR vulnerabilities occur when an application improperly verifies access controls, allowing users to access unauthorized resources.

### **Process & Logic:**

1. I attempted to access `/admin.php`, which redirected me away.
2. Using Burp Suite, I intercepted the request and found that the response still contained admin panel content.
3. By manually accessing the leaked URL, I bypassed authentication and gained admin access.

This demonstrated a **lack of proper authorization checks**.

---

## **Step 5: Session Hijacking via Token Manipulation**

### **Objective:** Escalate privileges by modifying session tokens.

Session tokens should be encrypted and integrity-checked to prevent manipulation. However, in this case, they were stored in plaintext hexadecimal format.

### **Process & Logic:**

1. I examined the session cookie and decoded it:

```bash
echo -n '757365723d6874622d7374646e743b726f6c653d75736572' | xxd -r -p
```

- `xxd -r -p`: Decodes hexadecimal data into plaintext.
- Output: `user=htb-stdnt;role=user`

2. I modified the session role to `admin` and re-encoded it:

```bash
echo -n 'user=htb-stdnt;role=admin' | xxd -p
```

3. I replaced my session cookie with the modified value, successfully escalating privileges.

This demonstrated a **lack of session integrity verification**, allowing unauthorized privilege escalation.

---

## **Lessons Learned & Mitigation Strategies**

### **Preventing User Enumeration:**

- Implement **generic error messages** for failed logins.
- Enforce **rate-limiting and progressive delays** on failed authentication attempts.

### **Defending Against Brute-Force Attacks:**

- Implement **account lockouts and MFA**.
- Require **stronger password policies**.

### **Securing OTP Mechanisms:**

- Use **6-digit+ OTPs** with **time-based expiration (TOTP)**.
- Apply **rate-limiting to OTP verification attempts**.

### **Mitigating IDOR Vulnerabilities:**

- Enforce **server-side access control validation**.
- Use **UUIDs instead of sequential numeric IDs**.

### **Securing Session Tokens:**

- Encrypt and sign tokens to prevent tampering.
- Implement **short-lived session expiration**.



