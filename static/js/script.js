document.addEventListener("DOMContentLoaded", function () {

    const fileInput = document.querySelector("input[type='file']");
    const form = document.querySelector("form");

    // Create elements dynamically
    const fileNameDisplay = document.createElement("p");
    const loader = document.createElement("p");

    loader.textContent = "⏳ Scanning file... Please wait";
    loader.style.display = "none";
    loader.style.color = "blue";

    form.appendChild(fileNameDisplay);
    form.appendChild(loader);

    // Show selected file name
    fileInput.addEventListener("change", function () {
        if (fileInput.files.length > 0) {
            fileNameDisplay.textContent = "Selected File: " + fileInput.files[0].name;
        }
    });

    // Show loader on submit
    form.addEventListener("submit", function () {
        loader.style.display = "block";
    });

});