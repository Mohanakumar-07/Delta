// ========================================
// Delta Voice Assistant - JavaScript
// ========================================

// Get API base URL from config (loaded before this script)
const getApiUrl = (endpoint) => {
  if (window.API_CONFIG) {
    return API_CONFIG.getUrl(endpoint);
  }
  return endpoint; // Fallback to relative URL
};

// Toggle profile dropdown
function toggleDropdown() {
  const dropdown = document.getElementById("profileDropdown");
  const isVisible = dropdown.style.display === "block";
  dropdown.style.display = isVisible ? "none" : "block";
  
  // Update chevron rotation
  const chevron = document.querySelector('.profile-chevron');
  if (chevron) {
    chevron.style.transform = isVisible ? 'rotate(0deg)' : 'rotate(180deg)';
  }
}

// Close dropdown if clicked outside
window.addEventListener('click', function (e) {
  const profile = document.querySelector('.profile-container');
  const dropdown = document.getElementById("profileDropdown");
  if (profile && !profile.contains(e.target)) {
    dropdown.style.display = 'none';
    const chevron = document.querySelector('.profile-chevron');
    if (chevron) chevron.style.transform = 'rotate(0deg)';
  }
});

// Update status indicator
function updateStatus(status, text) {
  const statusIndicator = document.getElementById('statusIndicator');
  const statusDot = statusIndicator?.querySelector('.status-dot');
  const statusText = statusIndicator?.querySelector('.status-text');
  
  if (statusText) statusText.textContent = text;
  
  if (statusDot) {
    statusDot.style.background = status === 'listening' ? '#fff6b3' : 
                                  status === 'processing' ? '#4CAF50' : 
                                  status === 'error' ? '#f44336' : '#fff6b3';
  }
}

// Activate assistant pulse animation
function setAssistantActive(active) {
  const pulse = document.getElementById('assistantPulse');
  if (pulse) {
    pulse.classList.toggle('active', active);
  }
}

// Add message to chat box
function addMessage(text, sender) {
  const chatBox = document.getElementById("chatBox");
  const message = document.createElement("div");
  message.className = `message ${sender}`;
  const bubble = document.createElement("div");
  bubble.className = `bubble ${sender}`;
  bubble.textContent = text;

  message.appendChild(bubble);
  chatBox.appendChild(message);
  chatBox.scrollTop = chatBox.scrollHeight;
}

// Logout function for API
async function handleLogout() {
  try {
    const response = await fetch(getApiUrl('/api/auth/logout'), {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (response.ok) {
      // Redirect to login or landing page
      window.location.href = '/';
    }
  } catch (error) {
    console.error('Logout error:', error);
    window.location.href = '/';
  }
}

// Voice recognition with wake word
let recognition;
let listening = false;
let isAwake = false; // Track if Delta has been awakened
let preferredVoice = null; // Store the preferred male voice

// Initialize and select a natural-sounding male voice
function initVoice() {
  const voices = speechSynthesis.getVoices();
  
  // Priority list of natural-sounding male voices
  const preferredVoices = [
    'Microsoft Guy Online (Natural)',   // Edge - very natural
    'Microsoft Ryan Online (Natural)',  // Edge - natural UK English
    'Google UK English Male',           // Chrome
    'Google US English',                // Chrome fallback
    'Microsoft David',                  // Windows default male
    'Microsoft Mark',                   // Windows
    'Alex',                             // macOS
    'Daniel'                            // macOS UK
  ];
  
  // Find the best available voice
  for (const name of preferredVoices) {
    const voice = voices.find(v => v.name.includes(name));
    if (voice) {
      preferredVoice = voice;
      console.log('Selected voice:', voice.name);
      break;
    }
  }
  
  // Fallback: find any male/en voice
  if (!preferredVoice) {
    preferredVoice = voices.find(v => 
      v.lang.startsWith('en') && 
      (v.name.toLowerCase().includes('male') || 
       v.name.toLowerCase().includes('guy') ||
       v.name.toLowerCase().includes('david') ||
       v.name.toLowerCase().includes('james'))
    ) || voices.find(v => v.lang.startsWith('en'));
    
    if (preferredVoice) console.log('Fallback voice:', preferredVoice.name);
  }
}

// Speak text with natural conversational tone
function speakText(text, onEndCallback) {
  // Cancel any ongoing speech
  speechSynthesis.cancel();
  
  const speech = new SpeechSynthesisUtterance(text);
  
  // Apply voice settings for natural conversation
  if (preferredVoice) {
    speech.voice = preferredVoice;
  }
  
  speech.rate = 1.05;      // Slightly faster for natural flow
  speech.pitch = 0.95;     // Slightly lower for male voice
  speech.volume = 1.0;
  
  if (onEndCallback) {
    speech.onend = onEndCallback;
  }
  
  speechSynthesis.speak(speech);
}

// Load voices (they load async in some browsers)
if (speechSynthesis.onvoiceschanged !== undefined) {
  speechSynthesis.onvoiceschanged = initVoice;
}
initVoice(); // Also try immediately

window.SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

if (window.SpeechRecognition) {
  recognition = new window.SpeechRecognition();
  recognition.continuous = true;
  recognition.interimResults = false;
  recognition.lang = "en-US";

  recognition.onresult = (event) => {
    const transcript = event.results[event.results.length - 1][0].transcript.trim().toLowerCase();
    console.log("Heard:", transcript);

    // Check for wake word "delta" if not already awake
    if (!isAwake) {
      if (transcript.includes("delta")) {
        isAwake = true;
        const cleaned = transcript.replace("delta", "").trim();
        
        if (cleaned) {
          // User said "delta" with a command
          processCommand(cleaned);
        } else {
          // User just said "delta" to wake up
          addMessage("I'm listening! What can I help you with?", "assistant");
          speakText("I'm listening! What can I help you with?");
          updateStatus('listening', 'Awake');
        }
      }
      // If not awake and no wake word, ignore the input
    } else {
      // Already awake, process any command directly
      const cleaned = transcript.replace("delta", "").trim(); // Remove delta if user still says it
      if (cleaned) {
        processCommand(cleaned);
      }
    }
  };

  // Function to process commands
  function processCommand(command) {
    addMessage(command, "user");
    updateStatus('processing', 'Processing...');
    setAssistantActive(true);

    fetch(getApiUrl("/update"), {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ message: command })
    })
    .then(res => {
      if (res.status === 401) {
        // Session expired, redirect to login
        window.location.href = '/login.html';
        throw new Error('Session expired');
      }
      return res.json();
    })
    .then(data => {
      if (data.reply) {
        addMessage(data.reply, "assistant");
        speakText(data.reply, () => {
          updateStatus('listening', 'Awake');
          setAssistantActive(false);
        });
      }
    })
    .catch(err => {
      console.error("Error fetching update:", err);
      if (err.message !== 'Session expired') {
        addMessage("Sorry, I couldn't process that request.", "assistant");
        updateStatus('error', 'Error');
        setTimeout(() => {
          updateStatus('listening', isAwake ? 'Awake' : 'Listening');
          setAssistantActive(false);
        }, 2000);
      }
    });
  }

  recognition.onerror = (event) => {
    console.error("Speech recognition error:", event.error);
    updateStatus('error', 'Error');
    setTimeout(() => updateStatus('listening', isAwake ? 'Awake' : 'Listening'), 2000);
  };

  recognition.onend = () => {
    if (listening) recognition.start(); // auto-restart
  };

  window.onload = () => {
    recognition.start();
    listening = true;
    isAwake = false; // Start in sleep mode, waiting for wake word
    updateStatus('listening', 'Listening');
    addMessage("Hello! Say 'Delta' to wake me up, then give your commands.", "assistant");
    console.log("Voice assistant ready.");
  };
} else {
  console.warn("Speech recognition not supported.");
  window.onload = () => {
    updateStatus('error', 'Not Supported');
    addMessage("Speech recognition is not supported in this browser. Please use Chrome or Edge.", "assistant");
  };
}
