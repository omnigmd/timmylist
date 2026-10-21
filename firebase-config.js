// Firebase project settings for The Timmylist. These values are public by design; the
// security rules (firestore.rules) are what protect the data.
window.TML_FIREBASE = {
  apiKey: "AIzaSyBFl28y-cG74HZvCHV1LDtb6ma_xkrNu_E",
  authDomain: "timmylist.firebaseapp.com",
  projectId: "timmylist",
  discord: true,
  appId: "1:343083999884:web:637d93fe45ee163e0911a9"
};

// Where the Discord functions live on this host. These are the Cloudflare Pages addresses.
// (On Netlify they were /.netlify/functions/discord-auth and /.netlify/functions/discord-link.)
window.TML_DISCORD_AUTH = "/api/discord-auth";
window.TML_DISCORD_LINK = "/api/discord-link";
