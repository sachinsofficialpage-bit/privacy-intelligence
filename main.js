function startScan() {
    window.location.href = "scan.html";
}


function chooseFile() {
    document.getElementById("fileInput").click();
}


async function beginScan() {

    const fileInput = document.getElementById("fileInput");
    const textInput = document.getElementById("textInput");

    const hasFile =
        fileInput &&
        fileInput.files &&
        fileInput.files.length > 0;

    const hasText =
        textInput &&
        textInput.value.trim() !== "";

    // Nothing entered
    if (!hasFile && !hasText) {
        alert("Please upload a document or paste some text first.");
        return;
    }

    // Don't allow both
    if (hasFile && hasText) {
        alert("Please use either a file OR text, not both.");
        return;
    }

    try {

        const formData = new FormData();

        // FILE SCAN
        if (hasFile) {

            formData.append(
                "file",
                fileInput.files[0]
            );

        }

        // TEXT SCAN
        else if (hasText) {

            formData.append(
                "text",
                textInput.value.trim()
            );

        }

        console.log("Sending scan request...");

        const response = await fetch(
            "http://127.0.0.1:8000/scan",
            {
                method: "POST",
                body: formData
            }
        );

        if (!response.ok) {

            const errorText = await response.text();

            throw new Error(
                `Backend error ${response.status}: ${errorText}`
            );
        }

        const result = await response.json();

        console.log("Scan result:", result);

        // Save backend result
        sessionStorage.setItem(
            "scanResult",
            JSON.stringify(result)
        );

        // Go to results page
        window.location.href = "results.html";

    } catch (error) {

        console.error("Scan failed:", error);

        alert(
            "Could not scan the file.\n\n" +
            error.message
        );
    }
}

/* Automatically move from Scanning → Results */

if (document.title.includes("Scanning")) {

    setTimeout(function () {

        const scanningSymbol =
            document.querySelector(".scanning-symbol");

        const scanIcon =
            document.getElementById("scanIcon");

        const scanTitle =
            document.querySelector(".scanning-page h1");

        const scanDescription =
            document.querySelector(".scanning-page > p");

        if (scanningSymbol) {

            scanningSymbol.classList.add("scan-complete");

        }

        if (scanIcon) {

            scanIcon.textContent = "✓";

        }

        if (scanTitle) {

            scanTitle.innerHTML = `
                Scan
                <span>complete.</span>
            `;

        }

        if (scanDescription) {

            scanDescription.textContent =
                "Sensitive information has been identified.";

        }

    }, 4500);


    setTimeout(function () {

        window.location.href = "results.html";

    }, 6000);

}


/* Results → Privacy Mask */

function openProtection() {

    window.location.href = "protect.html";

}

function continueToGate() {

    window.location.href = "gate.html";

}

function goBackToMask() {

    window.location.href = "protect.html";

}


function protectAndContinue() {

    window.location.href = "download.html";

}

function returnToResults() {

    window.location.href = "results.html";

}


function downloadDemo() {

    const message =
        document.getElementById("downloadMessage");

    if (message) {

        message.textContent =
            "Protected document prepared successfully.";

    }

}