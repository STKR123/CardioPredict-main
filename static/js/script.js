// Toggle chatbot visibility
document.addEventListener("DOMContentLoaded", () => {
  const toggleBtn = document.getElementById("chatbot-toggle");
  const popup = document.getElementById("chatbot-popup");
  const closeBtn = document.getElementById("close-chatbot");

  toggleBtn.addEventListener("click", () => {
    popup.classList.toggle("chatbot-hidden");
    popup.classList.toggle("chatbot-visible");
  });

  closeBtn.addEventListener("click", () => {
    popup.classList.add("chatbot-hidden");
    popup.classList.remove("chatbot-visible");
  });
});
