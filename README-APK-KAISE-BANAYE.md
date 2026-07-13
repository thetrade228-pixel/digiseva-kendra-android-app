# DigiSeva Kendra — Android App kaise banayein (APK)

Maine aapki website ko ek complete **Android app project** me convert kar diya hai —
browser jaisa kuch nahi dikhega: no address bar, apna app icon, apna splash screen,
back-button app jaise kaam karega. Bas final APK "compile" karne ke liye ek free
software chahiye hoga (Android Studio) jo is online chat environment me install
nahi ho sakta — isliye ye last step aapko apne computer par karna hoga. Sirf 10-15
minute lagenge.

## Step 1 — Android Studio install karein
1. https://developer.android.com/studio se **Android Studio** free download karein
2. Install karke ek baar open karein (pehli baar kuch components download karega, wifi pe rakhein)

## Step 2 — Project open karein
1. Is zip file ko extract karein
2. Android Studio open karein → **Open** → is folder ke andar wale **`android`** folder ko select karein (poore `dskapp` folder ko nahi, sirf uske andar `android` wala folder)
3. Thoda wait karein — Android Studio pehli baar "Gradle Sync" karega (2-5 minute, internet chahiye)

## Step 3 — APK banayein
1. Upar menu me: **Build → Build Bundle(s) / APK(s) → Build APK(s)**
2. Neeche-right corner me notification aayega "APK(s) generated successfully" — us par click karke **locate** karein
3. File milegi yahan: `android/app/build/outputs/apk/debug/app-debug.apk`
4. Ye APK file seedha kisi bhi Android phone me bhej ke install ho sakti hai (WhatsApp/Google Drive se)

## Play Store pe daalne ke liye (agla step, jab ready ho)
Play Store pe publish karne ke liye "debug" APK nahi, "signed release" APK/AAB chahiye hoga.
Android Studio me: **Build → Generate Signed Bundle / APK** se ek "keystore" (password-protected key) banega —
usko safe rakhein, wahi aapki app ki asli pehchaan hai future updates ke liye.
Phir Google Play Console (https://play.google.com/console) par one-time $25 registration
karke app submit kar sakte hain.

## Agar website content aage badalna ho
1. `www` folder ke andar apni `.html` files edit karein
2. Terminal me project folder ke andar: `npm install` (pehli baar) phir `npx cap sync android`
3. Android Studio me phir se Build → Build APK(s)

## Kya-kya already app-jaisa bana diya gaya hai
- Apna logo hi app icon aur splash screen hai
- Address bar / browser UI kahin nahi dikhega
- Status bar aapke brand color (blue) me hai
- Pinch-zoom band hai, text-select highlight/scrollbar hide hai (native feel)
- Back button app ke andar navigate karta hai; home screen par dobara dabane se "exit confirm" aata hai (jaise real apps me hota hai)

Koi bhi step me atkein to bata dijiye, main madad karta hoon.
