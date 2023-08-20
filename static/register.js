import {default as createMyModule} from "./emscript.js";
var Module; // initialise WASM
await createMyModule().then(function(mymod){
    Module = mymod;
});
var setup = Module.cwrap("setup",
    null,
    []
);
setup();

// setup functions we'll need
var passwordStrength = Module.cwrap("passwordStrength",
    "number",
    ["number", "number"]
);
var genKeypair = Module.cwrap("genKeypair",
    "number",
    ["number", "number", "number", "number"]
);
var makeIdentToken = Module.cwrap("makeIdentToken",
    "number",
    ["number", "number", "number", "number", "number", "number"]
);

// Handy function to make a POST request to the given URL, sending JSON data.
async function apiPost(url, data) {
    var resp = await fetch(url, {
        credentials: "same-origin",
        mode: "same-origin",
        method: "post",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
    })
    return await resp.json();
}

// Boilerplate code to completely create and add to page a Bootstrap "alert"
function popupAlert(alertType, alertText) {
    let al = document.createElement("div");
    al.classList.add("alert", alertType, "alert-dismissible", "fade", "show");
    al.innerText = alertText; // use a custom message
    let albutton = document.createElement("button");
    albutton.type = "button";
    albutton.classList.add("btn-close")
    albutton.setAttribute("data-bs-dismiss", "alert")
    al.appendChild(albutton);
    document.getElementById("alerts").appendChild(al);
}

// when the registration form gets submitted
document.getElementById("registerForm").onsubmit = (e) => {
    const formData = new FormData(e.target);
    
    var email = formData.get("email"); // retrieve data from form
    var password = formData.get("password");
    var confpassword = formData.get("confpassword");

    if (password !== confpassword) { // enforce passwords matching
        popupAlert("alert-danger", "Passwords must match.");
        return false;
    }

    var pwLen = password.length;
    var pwPtr = Module._malloc(pwLen);
    var tmpPtr = Module._malloc(pwLen);
    Module.writeAsciiToMemory(password, pwPtr, true);
    Module.writeAsciiToMemory(password, tmpPtr, true); // needed because checking strength scrambles password
    var strength = passwordStrength(tmpPtr, pwLen);
    Module._free(tmpPtr);
    if (strength < 8) { // enforce adequate password strength
        popupAlert("alert-danger", "Password is not strong enough.");
        return false;
    }

    var privPtr = Module._malloc(1194); // Time to generate the keys, client-side
    var priv = new Uint8Array(Module.HEAPU8.buffer, privPtr, 1194);
    var pubPtr = Module._malloc(270);
    var pub = new Uint8Array(Module.HEAPU8.buffer, pubPtr, 270);
    genKeypair(pubPtr, 270, privPtr, 1194);

    var tokenPtr = Module._malloc(32); // And identify ourselves with the server by sending token
    var token = new Uint8Array(Module.HEAPU8.buffer, tokenPtr, 32);
    makeIdentToken(pwPtr, pwLen, privPtr, 1194, tokenPtr, 32);

    // Try to send this all off
    apiPost("/api/register", {"email": email, "token": token, "pubkey": pub}).then((resp) => {
        if (resp["message"] !== "success") {
            // If it failed, provide a helpful message
            if (resp["error"] === "bad email") {
                popupAlert("alert-danger", "Malformed email.");
            } else {
                popupAlert("alert-danger", "Email already in use.");
            }
            document.getElementById("keyfile").hidden = true;
        } else {
            // Otherwise clear the alerts
            document.getElementById("alerts").replaceChildren();
            // And offer helpful instructions
            popupAlert("alert-success", "Success! Download your keyfile and save it in a known location");
            document.getElementById("keyfile").hidden = false;
        }
        
        return new Promise((r) => { // present the keyfile as a downloadable file
            const reader = new FileReader()
            reader.onload = () => r(reader.result)
            reader.readAsDataURL(new Blob([pub, priv]))
        })
    }).then((r) => {
        document.getElementById("keyfile").href = r; // And show the element on the page
    });

    return false; // stop redirecting to ?=
}

// Navigational aid - direct to login after downloading keyfile
document.getElementById("keyfile").onclick = () => {
    document.getElementById("proceed").hidden = false;
};

// Restricts error-causing characters
function fieldFilter(e) {
    let target = e.target;
    let bad = /[^ -~]/gi;
    target.value = target.value.replace(bad, '');
}

// Bind event listeners
document.getElementById('email').addEventListener('input', fieldFilter);
document.getElementById('password').addEventListener('input', fieldFilter);
document.getElementById('confpassword').addEventListener('input', fieldFilter);

// Refresh password strength metric every keypress
document.getElementById("password").onkeyup = () => {
    var str = document.getElementById("password").value;
    var buffer = Module._malloc(str.length);
    Module.writeAsciiToMemory(str, buffer, true); // send password to WASM memory

    let strength = passwordStrength(buffer, str.length);
    document.getElementById("PWstrength").value = strength; // update the meter

    Module._free(buffer); // tidy up memory
}