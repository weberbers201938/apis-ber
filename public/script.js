function copyCode() {
    var code = document.querySelector('.code-container code');
    var range = document.createRange();
    range.selectNode(code);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(range);
    document.execCommand('copy');
    window.getSelection().removeAllRanges();
    alert('Code copied to clipboard!');
}

// GUARD PROFILE
        document.getElementById("guardForm").addEventListener("submit", function(event) {
            event.preventDefault();
            const token = document.getElementById("token").value.trim();
            const enable = document.getElementById("enable").value.trim();
            if (token === '' || enable === '') {
                showError("Access token and options of True(on) & False(off) are required.");
                return;
            }
            guardProfile(token, enable);
        });

function guardProfile(token, enable) {
            const loadingDiv = document.getElementById("loading");
            const responseDiv = document.getElementById("response");
            const errorDiv = document.getElementById("error");
            const axios = require('axios');
            loadingDiv.style.display = "block";
            responseDiv.style.display = "none";
            errorDiv.style.display = "none";

            axios.post("/shield", { token: token, enable: enable })
            .then(response => {
                const responseData = response.data;
                responseDiv.innerHTML =  responseData;
                responseDiv.style.display = "block";
                loadingDiv.style.display = "none";
                if (responseData && responseData.success) {
                    alert("Successfully Guarded! Please check your profile.");
                }
            })
            .catch(error => {
                console.error("Error:", error);
                loadingDiv.style.display = "none";
                if (error.response && error.response.status === 400) {
                    showError("Invalid access token or options. Please check and try again.");
                } else {
                    showError("An error occurred. Please try again later.");
                }
            });
        }

function showError(message) {
            const errorDiv = document.getElementById("error");
            errorDiv.innerHTML = message;
            errorDiv.style.display = "block";
}
