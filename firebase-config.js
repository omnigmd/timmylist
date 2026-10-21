// Firebase project settings for The Timmylist. These values are public by design; the
// security rules (firestore.rules) are what protect the data.
window.TML_FIREBASE = {
  apiKey: "AIzaSyBFl28y-cG74HZvCHV1LDtb6ma_xkrNu_E",
  authDomain: "timmylist.firebaseapp.com",
  projectId: "timmylist",
  discord: true,
  appId: "1:343083999884:web:637d93fe45ee163e0911a9"
};

// Discord linking (optional). Set this to "/.netlify/functions/discord-link" on hosts that run the functions (Vercel or Netlify).
// Leave it empty on hosts without functions (the Link Discord button is then switched off).
window.TML_DISCORD_LINK = "/.netlify/functions/discord-link";
