"use strict";

const API = "api/receipts/data.php";
const code = new URLSearchParams(location.search).get("code") || "";

let receipt = null;

const $ = (selector) => document.querySelector(selector);

function esc(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function show(message, type = "info") {
    const notice = $("#notice");
    notice.className = "notice show " + type;
    notice.textContent = message;
}

function money(data) {
    return `${data.currency_symbol || ""} ${Number(data.amount_paid || 0).toFixed(2)}`;
}

function prettyDate(value) {
    if (!value) {
        return "—";
    }

    const date = new Date(String(value).replace(" ", "T"));

    return Number.isNaN(date.getTime())
        ? String(value)
        : date.toLocaleString();
}

async function load() {
    if (!/^[a-f0-9]{64}$/i.test(code)) {
        $("#loader").style.display = "none";
        show(
            "This receipt page requires a valid unique receipt code. It cannot be opened without one.",
            "error"
        );
        return;
    }

    try {
        const response = await fetch(
            `${API}?code=${encodeURIComponent(code)}&_=${Date.now()}`,
            {
                credentials: "same-origin",
                cache: "no-store",
                headers: {
                    Accept: "application/json"
                }
            }
        );

        const text = await response.text();

        let json;

        try {
            json = JSON.parse(text);
        } catch {
            throw new Error("The receipt server returned an invalid response.");
        }

        if (!response.ok || json.success !== true) {
            throw new Error(
                json.message || "This receipt is unavailable."
            );
        }

        receipt = json.receipt;

        $("#loader").style.display = "none";
        $("#receipt").style.display = "block";

        $("#intro").textContent =
            `Hello ${receipt.full_name || receipt.username || "customer"}. ` +
            `Your payment for ${receipt.service_name} was successfully received by LOVEMI.`;

        $("#receiptNumber").textContent =
            receipt.receipt_number || "—";

        $("#paymentReference").textContent =
            receipt.payment_reference || "—";

        $("#customer").textContent =
            receipt.full_name || receipt.username || "—";

        $("#service").textContent =
            receipt.service_name || "—";

        $("#method").textContent =
            (receipt.payment_method || "payment").toUpperCase();

        $("#transaction").textContent =
            receipt.gateway_transaction_id || "—";

        $("#paidAt").textContent =
            prettyDate(receipt.paid_at || receipt.issued_at);

        $("#period").textContent =
            `${prettyDate(receipt.start_at)} → ${prettyDate(receipt.end_at)}`;

        $("#total").textContent = money(receipt);
    } catch (error) {
        $("#loader").style.display = "none";

        show(
            error.message || "Unable to load receipt.",
            "error"
        );
    }
}

async function downloadPdf() {
    if (!receipt) {
        show("Receipt is not loaded yet.", "error");
        return;
    }

    if (!window.html2canvas || !window.jspdf) {
        show(
            "PDF libraries could not be loaded. Use your browser print function instead.",
            "error"
        );

        window.print();
        return;
    }

    const element = $("#receipt");

    const canvas = await html2canvas(element, {
        scale: 2,
        useCORS: true,
        backgroundColor: "#ffffff"
    });

    const { jsPDF } = window.jspdf;

    const pdf = new jsPDF("p", "mm", "a4");

    const margin = 10;
    const pageWidth = 210 - margin * 2;

    const imageHeight =
        canvas.height * pageWidth / canvas.width;

    const pagePixelHeight = Math.floor(
        canvas.width *
        (297 - margin * 2) /
        pageWidth
    );

    let sourceY = 0;
    let remainingHeight = imageHeight;

    while (remainingHeight > 0) {
        const slice = document.createElement("canvas");

        slice.width = canvas.width;

        slice.height = Math.min(
            pagePixelHeight,
            canvas.height - sourceY
        );

        const context = slice.getContext("2d");

        context.drawImage(
            canvas,
            0,
            sourceY,
            canvas.width,
            slice.height,
            0,
            0,
            slice.width,
            slice.height
        );

        const sliceHeight =
            slice.height * pageWidth / slice.width;

        pdf.addImage(
            slice.toDataURL("image/png"),
            "PNG",
            margin,
            margin,
            pageWidth,
            sliceHeight
        );

        remainingHeight -= sliceHeight;
        sourceY += slice.height;

        if (remainingHeight > 0) {
            pdf.addPage();
        }
    }

    pdf.save(
        `${receipt.receipt_number || "LOVEMI-receipt"}.pdf`
    );
}

$("#downloadPdf").addEventListener("click", () => {
    downloadPdf().catch((error) => {
        show(
            error.message || "Could not generate PDF.",
            "error"
        );
    });
});

$("#returnBtn").addEventListener("click", () => {
    location.href = "dashboard.html";
});

load();