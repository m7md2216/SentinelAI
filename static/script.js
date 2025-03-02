function sendMessage() {
    let inputField = document.getElementById("user-input");
    let message = inputField.value.trim();
    let chatBox = document.getElementById("chat-box");

    if (message === "") return;

    // Add user message to chat
    chatBox.innerHTML += `<div class='user-message'>You: ${message}</div>`;

    // Clear input field
    inputField.value = "";

    // Send message to Flask backend
    fetch("/chat", {
        method: "POST",
        body: JSON.stringify({ message: message }),
        headers: { "Content-Type": "application/json" }
    })
    .then(response => response.json())
    .then(data => {
        chatBox.innerHTML += `<div class='bot-message'>AI: ${data.response}</div>`;
        chatBox.scrollTop = chatBox.scrollHeight;
    })
    .catch(error => console.error("Error:", error));
}
