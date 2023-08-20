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
// Bootstrap code to initialise the tooltips
const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))

// Initialise the functions from the library that we're going to use
var passwordStrength = Module.cwrap("passwordStrength",
    "number",
    ["number", "number"]
);
var pwSuggest = Module.cwrap("pwSuggest",
    "number",
    ["number", "number", "number", "number", "number", "number", "number", "number"]
);
var encryptPW = Module.cwrap("encryptPW",
    "number",
    ["number", "number", "number", "number", "number", "number"]
);
var decryptPW = Module.cwrap("decryptPW",
    "number",
    ["number", "number", "number", "number", "number", "number"]
);

// Handy function to make a POST request to the given URL, sending JSON data.
async function apiPost(url, data) {
    let resp = await fetch(url, {
        credentials: "same-origin",
        mode: "same-origin",
        method: "post",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
    })
    return await resp.json()
}

// Function to log the user out, followed by clearing up cached data
function doLogout() {
    apiPost("/api/logout", {}).then(() => {
        sessionStorage.removeItem("priv");
        sessionStorage.removeItem("pub");
        window.location.href = "/login.html"
    });
}

// A general filter to be placed on text input, that removes non-ASCII characters
function fieldFilter(e) {
    let target = e.target;
    let bad = /[^ -~]/gi;
    target.value = target.value.replace(bad, '');
}

// perform a full decryption flow for a password, given just its PID
async function fullDecryptPW(pid) {
    let resp = await apiPost("/api/getpass", {"pid": pid});

    for (let x = 0; x < 256; x++) { // copy API data into local buffer
        buf256A[x] = resp["data"][x];
    };
    decryptPW(buf256BPtr, 256, privPtr, firstNonZero+1, buf256APtr, 256);
    let index = 0;
    while (index < 256) { // Find the length of the decrypted password
        if (buf256B[index] === 0) {
            break;
        }
        index++;
    }
    
    let decrypted = String.fromCharCode(...buf256B.slice(0, index));
    for (let x = 0; x < 256; x++) { // Clear for future use
        buf256B[x] = 0;
    }
    return decrypted;
}

// Function to replace given row's dots, and put the password in its place
function revealPW(ev) {
    let target = ev.target;
    let tr = target.parentElement.parentElement;

    let otherTRs = document.getElementById("passwords").getElementsByTagName("tr");
    for (let x = 0; x < otherTRs.length; x++) { // Reset all the other entries to have dots
        otherTRs[x].children[2].innerText = "........";
    }

    let pid = parseInt(tr.id.substr(1));
    fullDecryptPW(pid).then((decpw) => {
        const PWfield = tr.children[2];
        PWfield.innerText = decpw;
        navigator.clipboard.writeText(decpw); // Copy the password to clipboard
    });
}

var deleting; // holds the PID of the password to be deleted

// Function to ask for confirmation to actually delete the password
function deletePW(ev) {
    let target = ev.target;
    let tr = target.parentElement.parentElement;

    let pid = parseInt(tr.id.substr(1));
    deleting = pid;
    let modalEl = document.getElementById('confirmDel'); // Bootstrap to open modal
    let modal = new bootstrap.Modal(modalEl, {});
    modal.show();
}

// If that modal gets the go-ahead, actually perfom the deletion
document.getElementById("confirmDelBtn").onclick = () => {
    apiPost("/api/delpass", {"pid": deleting}).then((resp) => {
        console.log(resp);
        fetchPWs(); // Show changes by refreshing the password list
    })
}

// Called to show/hide action buttons when the mouse hovers over a row
function doButtons(ev) {
    const state = ev.type;
    const buttons = ev.target.children[3].children;
    for (let x = 0; x < 3; x++) { // x < 4
        let button = buttons[x];
        if (state === "mouseenter") { // If mouse is over them, show them
            button.style.visibility = "";
        } else { // otherwise hide
            button.style.visibility = "hidden";
        }
    }
}

// Event handler when a category drop-down item is selected, to fill it into the box
function fillCategory(ev) {
    let fillWith = ev.target.innerText;
    document.getElementById("PWcategory").value = fillWith;
}

var PIDediting = null; // State variable to indicate which PID is being edited

// Function is called when a user requests to edit a password
function editPW(ev) {
    let target = ev.target;
    let tr = target.parentElement.parentElement;
    // Fetch metadata to be displayed in new form
    let name = tr.children[0].innerText;
    let user = tr.children[1].innerText;
    let category = tr.parentElement.parentElement.previousElementSibling.innerText;
    let pid = parseInt(tr.id.substr(1));
    
    fullDecryptPW(pid).then((decpw) => {
        document.getElementById("addPWbutton").click(); // launch the add password modal (hacky solution)
        document.getElementById("addPasswordLabel").innerText = "Edit Password"; // rename it (hacky solution)
        document.getElementById("PWname").value = name;
        document.getElementById("PWuser").value = user;
        document.getElementById("PWcontent").value = decpw; // importantly, put in the decrypted password
        document.getElementById("PWcategory").value = category;
        PIDediting = pid;
    });
}

// Function to refresh the main list of password entries
function fetchPWs() {
    apiPost("/api/listpass", {}).then((resp) => {
        // Initialise, reset the main list (and also categories drop down)
        let groups = resp["data"];
        let container = document.getElementById("passwords");
        container.replaceChildren();
        let catDropDown = document.getElementById("categoriesDropDown");
        catDropDown.replaceChildren();
        let AcatLi = document.createElement("li");
        let AcatA = document.createElement("a")
        AcatA.classList.add("dropdown-item");
        AcatA.href = "#";
        AcatA.innerText = "General";
        AcatA.onclick = fillCategory;
        AcatLi.appendChild(AcatA);
        catDropDown.appendChild(AcatLi);
        
        // Iterate through CATEGORIES first
        for (const [category, list] of Object.entries(groups)) {
            // Make section on page for category
            let title = document.createElement("h2");
            title.innerText = category;
            container.appendChild(title);

            // Append this category to the categories picker drop-down
            let catLi = document.createElement("li");
            let catA = document.createElement("a")
            catA.classList.add("dropdown-item");
            catA.href = "#";
            catA.innerText = category;
            catA.onclick = fillCategory;
            catLi.appendChild(catA);
            catDropDown.appendChild(catLi);

            // Set up password table for this category
            let table = document.createElement("table");
            table.classList.add("table", "table-striped");
            let tbody = document.createElement("tbody");

            // Now iterate through individual PASSWORDS
            for (const [pid, pdata] of Object.entries(list)) {
                // Make a row for this password
                let tr = document.createElement("tr");
                tr.classList.add("row", "w-100", "w-100");
                tr.id = pid;
                tr.onmouseenter = doButtons;
                tr.onmouseleave = doButtons;
                
                // Set up columns for name, username, password (dots)
                let td0 = document.createElement("td");
                td0.classList.add("col-md-4", "overflow-x-auto");
                td0.innerText = pdata["name"];
                let td1 = document.createElement("td");
                td1.classList.add("col-md", "overflow-x-auto");
                td1.innerText = pdata["user"];
                let td2 = document.createElement("td");
                td2.classList.add("col-md", "overflow-x-auto");
                td2.innerText = "........";
                
                // Set up actions column
                let td3 = document.createElement("td");
                td3.classList.add("col-md-auto", "overflow-x-auto");
                let edit = document.createElement("button");
                edit.innerText = "Edit";
                edit.style.visibility = "hidden";
                edit.classList.add("btn", "btn-outline-primary")
                edit.onclick = editPW;
                let copy = document.createElement("button");
                copy.innerText = "Copy";
                copy.style.visibility = "hidden";
                copy.classList.add("btn", "btn-outline-primary")
                copy.onclick = revealPW;
                //let share = document.createElement("button");
                //share.innerText = "Share";
                //share.style.visibility = "hidden";
                //share.classList.add("btn", "btn-outline-primary")
                let del = document.createElement("button");
                del.innerText = "Delete";
                del.style.visibility = "hidden";
                del.classList.add("btn", "btn-outline-danger")
                del.onclick = deletePW;
                td3.appendChild(edit); // And append all the children where they need to go
                td3.appendChild(copy);
                //td3.appendChild(share);
                td3.appendChild(del);

                tr.appendChild(td0);
                tr.appendChild(td1);
                tr.appendChild(td2);
                tr.appendChild(td3);
                tbody.appendChild(tr);
            }
            table.appendChild(tbody);
            container.appendChild(table);
        }
    })
}

// Borrowed from https://stackoverflow.com/questions/8670909/
async function sha256(source) {
    const sourceBytes = new TextEncoder().encode(source);
    const digest = await crypto.subtle.digest("SHA-256", sourceBytes);
    const resultBytes = [...new Uint8Array(digest)];
    return resultBytes.map(x => x.toString(16).padStart(2, '0')).join("");
}

var numComp; // state variable to count the number of compromised passwords encountered

// Runs the password health check system
function doHealth() {
    // Initialise, clear the table, grab a list of all passwords
    numComp = 0;
    const healthTB = document.getElementById("healthTB");
    healthTB.replaceChildren();
    let allTRs = document.getElementById("passwords").getElementsByTagName("tr");
    if (allTRs.length === 0) {
        document.getElementById("statement").innerText = "0 passwords found in breaches.";
        return;
    }
    // Iterate through every password
    for (let x = 0; x < allTRs.length; x++) {
        // Perform a decryption flow on each one
        const pid = parseInt(allTRs[x].id.substr(1));
        const name = allTRs[x].children[0].innerText; // (save metadata for later)
        const user = allTRs[x].children[1].innerText;
        fullDecryptPW(pid).then((decpw) => {

            sha256(decpw).then((hash) => { // hash it and send to server (securely)
                apiPost("/api/findmatch", {"hash": hash}).then((resp) => {
                    if (resp["message"] === "yes") { // If it has been involved in a breach
                        numComp += 1;
                        let msg;
                        if (numComp === 0) { // Format human text
                            msg = "0 passwords found in breaches.";
                        } else if (numComp === 1) {
                            msg = "1 password found in breaches:";
                        } else {
                            msg = `${numComp} passwords found in breaches:`;
                        }
                        document.getElementById("statement").innerText = msg;

                        let tr = document.createElement("tr"); // Add this password entry into compromised table
                        tr.classList.add("row", "w-100", "w-100");
                        let td0 = document.createElement("td");
                        td0.classList.add("col-md", "overflow-x-auto");
                        let td1 = document.createElement("td");
                        td1.classList.add("col-md", "overflow-x-auto");
                        let td2 = document.createElement("td");
                        td2.classList.add("col-md", "overflow-x-auto");

                        td0.innerText = name;
                        td1.innerText = user;
                        td2.innerText = decpw;
            
                        tr.appendChild(td0); // Append children where they need to go
                        tr.appendChild(td1);
                        tr.appendChild(td2);
                        healthTB.appendChild(tr);
                    }
                })
            })
        })
    }
}

// Display a password strength meter, updates every keystroke
document.getElementById("PWcontent").onkeyup = () => {
    var str = document.getElementById("PWcontent").value;
    var buffer = Module._malloc(str.length);
    Module.writeAsciiToMemory(str, buffer, true);

    let strength = passwordStrength(buffer, str.length);
    document.getElementById("PWstrength").value = strength;

    Module._free(buffer); // always tidy up our memory
}

// General purpose buffer for generating a password
var pwPtr = Module._malloc(200);
var pw = new Uint8Array(Module.HEAPU8.buffer, pwPtr, 200);

document.getElementById("triggerPWsuggest").onclick = () => {
    // Fetch all the options from the HTML
    let len = document.getElementById("len").value;
    let upper = document.getElementById("upper").checked ? 1 : 0;
    let lower = document.getElementById("lower").checked ? 1 : 0;
    let nums = document.getElementById("nums").checked ? 1 : 0;
    let extra = document.getElementById("extra").value;
    let extraPtr = Module._malloc(extra.length);
    Module.writeAsciiToMemory(extra, extraPtr, true);
    let unamb = document.getElementById("unamb").checked ? 1 : 0;

    // Perform the algorithm
    pwSuggest(pwPtr, len, upper, lower, nums, extraPtr, extra.length, unamb);
    document.getElementById("PWcontent").value = String.fromCharCode(...pw)
    for (let x = 0; x < 200; x++) { // reset buffer for future use
        pw[x] = 0;
    }
    Module._free(extraPtr); // tidy up memory
    return false; // stop redirecting to ?=
}

// Perform sanitisation on the extra field
document.getElementById('extra').addEventListener('input', fieldFilter);

// Allocate buffers for public/private keypair, and general purpose RSA buffers
var pubPtr = Module._malloc(270);
var pub = new Uint8Array(Module.HEAPU8.buffer, pubPtr, 270);
var privPtr = Module._malloc(1194);
var priv = new Uint8Array(Module.HEAPU8.buffer, privPtr, 1194);
var buf256APtr = Module._malloc(256);
var buf256A = new Uint8Array(Module.HEAPU8.buffer, buf256APtr, 256);
var buf256BPtr = Module._malloc(256);
var buf256B = new Uint8Array(Module.HEAPU8.buffer, buf256BPtr, 256);

if (sessionStorage.getItem("priv") === null || sessionStorage.getItem("pub") === null) {
    // if the keys cannot be found in sessionStorage (i.e. we didn't properly login)
    doLogout();
}
const sPub = JSON.parse(sessionStorage.pub);
const sPriv = JSON.parse(sessionStorage.priv);
for (let x = 0; x < 270; x++) { // copy data to local, WASM buffers
    pub[x] = sPub[x]
}
for (let x = 0; x < 1194; x++) {
    priv[x] = sPriv[x]
}
var firstNonZero = 1193; // find, backwards, last non-zero byte of private key. essential to make RSA work
while (priv[firstNonZero] == 0) {
    firstNonZero -= 1;
}

fetchPWs(); // show the user their passwords when they login

// Function called when adding a new password
document.getElementById("createPW").onsubmit = (e) => {
    // Load data from the form
    const formData = new FormData(e.target);
    let PWcategory = formData.get("PWcategory");
    let PWuser = formData.get("PWuser");
    let PWname = formData.get("PWname");
    let PWcontent = formData.get("PWcontent");
    let contentPtr = Module._malloc(PWcontent.length);
    Module.writeAsciiToMemory(PWcontent, contentPtr, true); // transfer plaintext password to WASM memory

    encryptPW(buf256APtr, 256, pubPtr, 270, contentPtr, PWcontent.length); // perform the encryption flow
    // Send this data off to the server
    apiPost("/api/addpass", {"data": buf256A, "name": PWname, "category": PWcategory, "user": PWuser}).then((resp) => {
        if (resp["message"] !== "success") {
            console.log(resp); // if we get an error (which shouldn't happen)
        } else {
            e.target.reset(); // clear the form
            document.getElementById("addPasswordLabel").innerText = "Add Password"; // reset just in case it got changed
            // Close the add password modal
            let modalEl = document.getElementById('addPassword');
            let modal = bootstrap.Modal.getInstance(modalEl);
            modal.hide();
            if (PIDediting) { // delete the old password if this was *actually* an edit operation
                apiPost("/api/delpass", {"pid": PIDediting}).then(() => {
                    PIDediting = null;
                    fetchPWs();
                    return;
                })
            }
            
            fetchPWs(); // display the changes
        }
    })

    return false; // stop redirecting to ?=
}

// Reset the form when it was being used for editing, and now should be used for adding.
document.getElementById("modalcloser").onclick = () => {
    PIDediting = null;
    document.getElementById("addPasswordLabel").innerText = "Add Password";
}

// Function to show/hide the password suggestion controls
function pwSugToggle(ev) {
    let txt = "";
    if (ev.target.checked) {
        txt = "";
    } else {
        txt = "none";
    }
    document.getElementById("pwSuggestEl").style.display = txt;
}

// Homogenise search strings to increase probability of matches
function sanitise(str) {
    return str
        .replace(/'/g,'')
        .trim()
        .replace(/\s+/g, " ")
        .toUpperCase();
}

// Update password entries in real-time when searching for them
document.getElementById("PWsearch").onkeyup = () => {
    const filter = sanitise(document.getElementById("PWsearch").value);

    let trs = document.getElementById("passwords").getElementsByTagName("tr");

    // For each password entry
    for (let i = 0; i < trs.length; i++) {
        let tds = trs[i].getElementsByTagName("td");
        let txt = sanitise(tds[0].innerText + " " + tds[1].innerText);
        if (txt.indexOf(filter) > -1) { // try to find the string, if we do: show
            trs[i].style.display = "";
        } else { // otherwise hide
            trs[i].style.display = "none";
        }
    }
}

// Bind handlers
document.getElementById('healthBtn').onclick = doHealth;
document.getElementById('logoutBtn').onclick = doLogout;
document.getElementById('pwSuggestEnable').onclick = pwSugToggle;
document.getElementById('PWname').addEventListener('input', fieldFilter);
document.getElementById('PWcontent').addEventListener('input', fieldFilter);
document.getElementById('PWuser').addEventListener('input', fieldFilter);
document.getElementById('PWcategory').addEventListener('input', fieldFilter);
document.getElementById('len').oninput = () => {
    // Display the slider value to the right of the slider. usability.
    document.getElementById('lenValue').innerText = document.getElementById('len').value;
}