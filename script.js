function getPassphrase() {
    const first = document.getElementById("firstName").value.trim().toLowerCase();
    const last = document.getElementById("lastName").value.trim().toLowerCase();

    if (/[^a-z]/.test(first) || /[^a-z]/.test(last)) {
        alert("Names should only include alphabetic characters.");
        return "";
    }

    return first + last;
}

function constantTimeCompare(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}

function setLoading(show) {
    const loadingBar = document.getElementById("loadingBar");
    const output = document.getElementById("output");
    const inputs = [...document.querySelectorAll("textarea, input, button")];
    if (show) {
        loadingBar.style.display = "block";
        output.innerText = "⏳ Processing, please wait...";
        inputs.forEach(el => el.disabled = true);
    } else {
        loadingBar.style.display = "none";
        document.getElementById("loadingProgress").style.width = "0%";
        inputs.forEach(el => el.disabled = false);
    }
}

function animateLoading(duration = 3000) {
    const progress = document.getElementById("loadingProgress");
    let start = null;
    return new Promise(resolve => {
        function step(timestamp) {
            if (!start) start = timestamp;
            let elapsed = timestamp - start;
            let percent = Math.min((elapsed / duration) * 100, 100);
            progress.style.width = percent + "%";
            if (elapsed < duration) {
                window.requestAnimationFrame(step);
            } else {
                resolve();
            }
        }
        window.requestAnimationFrame(step);
    });
}

async function encrypt() {
    setLoading(true);
    await animateLoading(3000);

    try {
        const message = document.getElementById("message").value;
        const passphrase = getPassphrase();

        if (!message || !passphrase) {
            setLoading(false);
            document.getElementById("output").innerText = "❗ Enter a message and your full name.";
            return;
        }

        const salt = CryptoJS.lib.WordArray.random(16);
        const iv = CryptoJS.lib.WordArray.random(16);

        const key = CryptoJS.PBKDF2(passphrase, salt, {
            keySize: 256 / 32,
            iterations: 250000
        });

        const encrypted = CryptoJS.AES.encrypt(message, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        }).ciphertext;

        const hmacKey = CryptoJS.PBKDF2(passphrase, salt, {
            keySize: 256 / 32,
            iterations: 100000
        });

        const hmac = CryptoJS.HmacSHA256(encrypted, hmacKey);

        const b64salt = salt.toString(CryptoJS.enc.Base64);
        const b64iv = iv.toString(CryptoJS.enc.Base64);
        const b64cipher = CryptoJS.enc.Base64.stringify(encrypted);
        const b64hmac = hmac.toString(CryptoJS.enc.Base64);

        const output = [b64salt, b64iv, b64cipher, b64hmac].join(":");

        setLoading(false);
        document.getElementById("output").innerText = output;

    } catch (e) {
        setLoading(false);
        document.getElementById("output").innerText = "❌ Encryption error: " + e.message;
    }
}

async function decrypt() {
    setLoading(true);
    await animateLoading(3000);

    try {
        const input = document.getElementById("message").value;
        const passphrase = getPassphrase();

        if (!input || !passphrase) {
            setLoading(false);
            document.getElementById("output").innerText = "❗ Enter encrypted message and your full name.";
            return;
        }

        const parts = input.split(":");
        if (parts.length !== 4) {
            setLoading(false);
            document.getElementById("output").innerText = "❗ Invalid input format.";
            return;
        }

        const [b64salt, b64iv, b64cipher, b64hmac] = parts;

        const salt = CryptoJS.enc.Base64.parse(b64salt);
        const iv = CryptoJS.enc.Base64.parse(b64iv);
        const ciphertext = CryptoJS.enc.Base64.parse(b64cipher);
        const hmacGiven = b64hmac;

        const key = CryptoJS.PBKDF2(passphrase, salt, {
            keySize: 256 / 32,
            iterations: 250000
        });
        const hmacKey = CryptoJS.PBKDF2(passphrase, salt, {
            keySize: 256 / 32,
            iterations: 100000
        });

        const hmacCheck = CryptoJS.HmacSHA256(ciphertext, hmacKey).toString(CryptoJS.enc.Base64);

        if (!constantTimeCompare(hmacCheck, hmacGiven)) {
            setLoading(false);
            document.getElementById("output").innerText = "❌ HMAC validation failed — wrong name or corrupted message.";
            return;
        }

        const decrypted = CryptoJS.AES.decrypt({
                ciphertext: ciphertext
            },
            key, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            }
        ).toString(CryptoJS.enc.Utf8);

        if (!decrypted) throw new Error("Decryption failed");

        setLoading(false);
        document.getElementById("output").innerText = decrypted;

    } catch (e) {
        setLoading(false);
        document.getElementById("output").innerText = "❌ Decryption failed — wrong name or corrupted message.";
    }
}

function copyOutput() {
    const text = document.getElementById("output").innerText;
    navigator.clipboard.writeText(text).then(() => {
        alert("Copied to clipboard!");
    }).catch(() => {
        alert("Failed to copy.");
    });
}
