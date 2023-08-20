import {default as createMyModule} from "./emscript.js";
var Module; // setup WASM stuff
await createMyModule().then(function(mymod){
    Module = mymod;
});
var setup = Module.cwrap("setup",
    null,
    []
);
setup();

// register function to use
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

// When submitting the login form:
document.getElementById("loginForm").onsubmit = (e) => {
    const formData = new FormData(e.target);
    
    var email = formData.get("email"); // load fields from form data
    var password = formData.get("password");
    var keyfile = formData.get("keyfile");

    var reader = new FileReader();
    reader.onloadend = function() { // when the keyfile gets loaded in
        var arrayBuffer = this.result;
        var array = new Uint8Array(arrayBuffer); // load keyfile as Uint8Array
        if (array.length != (270 + 1194)) { // ensure it looks like the right file
            popupAlert("alert-danger", "Malformed keyfile.")
            return false;
        }
        
        var pubPtr = Module._malloc(270); // allocate space for public key
        var pub = new Uint8Array(Module.HEAPU8.buffer, pubPtr, 270);
        for (var x = 0; x < 270; x++) {
            pub[x] = array[x]; // copy it in
        }
        var privPtr = Module._malloc(1194); // and for private
        var priv = new Uint8Array(Module.HEAPU8.buffer, privPtr, 1194);
        for (var x = 0; x < 1194; x++) {
            priv[x] = array[x + 270]; // copy it in
        }
        var pwLen = password.length;
        var pwPtr = Module._malloc(pwLen);
        Module.writeAsciiToMemory(password, pwPtr, true); // write plaintext password to WASM memory
        var tokenPtr = Module._malloc(32);
        var token = new Uint8Array(Module.HEAPU8.buffer, tokenPtr, 32);
        // Call WASM routine to generate our auth token
        makeIdentToken(pwPtr, pwLen, privPtr, 1194, tokenPtr, 32);

        // Try to login with this
        apiPost("/api/login", {"email": email, "token": token}).then((resp) => {
            if (resp["message"] !== "success") { // If failed:
                // Display a helpful error message
                if (resp["error"] === "bad email") {
                    popupAlert("alert-danger", "Malformed email.");
                } else {
                    popupAlert("alert-danger", "Incorrect email or password.");
                }
                
            } else {
                // Otherwise, transfer the public/private keypair to the index page
                sessionStorage.priv = JSON.stringify(priv);
                sessionStorage.pub = JSON.stringify(pub);
                window.location.href = "/index.html"
            }
        });

    }
    reader.readAsArrayBuffer(keyfile); // Kicks off the file reading

    return false; // Stop redirecting to ?=
}

// Restricts error-causing characters
function fieldFilter(e) {
    let target = e.target;
    let bad = /[^ -~]/gi;
    target.value = target.value.replace(bad, '');
}

// Bind event listeners
document.getElementById('email').addEventListener('input', fieldFilter);
document.getElementById('password').addEventListener('input', fieldFilter);