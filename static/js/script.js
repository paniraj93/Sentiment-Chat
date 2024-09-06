function loadChat(friendUsername) {
    document.getElementById('recipient').value = friendUsername;
    fetch(`/get_messages/${friendUsername}`)
        .then(response => response.text())
        .then(html => {
            document.getElementById('chat-messages').innerHTML = html;
        });
}

function sendMessage() {
    const form = document.getElementById('message-form');
    const formData = new FormData(form);

    fetch('/send_message', {
        method: 'POST',
        body: formData
    }).then(() => {
        form.reset();
        loadChat(document.getElementById('recipient').value);
    });

    return false;
}