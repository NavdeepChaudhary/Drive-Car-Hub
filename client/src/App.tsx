import React, { useState, useEffect, useMemo, useRef } from 'react';
import AdminPage from './components/AdminPage';
import SellCarPage from './components/SellCarPage';

// --- Type Definitions ---

interface CarListing {
    id: string;
    make: string;
    model: string;
    year: number;
    price: number;
    mileage: number;
    description: string;
    imageUrls: string[];
    isFeatured?: boolean;
    sellerUid: string;
    // NEW: Status tracking
    status: 'available' | 'sold';
    buyerUid?: string;
    purchaseDate?: string;
    createdAt?: string;
}

interface AppUser {
    uid: string;
    email: string;
    fullName?: string;
    mobileNumber?: string;
    isAdmin?: boolean;
}

interface ChatMessage {
    id: string;
    threadId: string;
    senderUid: string;
    text: string;
    timestamp: number;
}

interface ChatThread {
    id: string;
    listingId: string;
    listingTitle: string;
    buyerUid: string;
    sellerUid: string;
    buyerEmail: string;
    sellerEmail: string;
    lastMessage?: string;
    lastTimestamp: number;
}

type View = 'home' | 'user-dashboard' | 'listings' | 'auth' | 'sell' | 'detail' | 'inbox' | 'chat' | 'invoice' | 'admin' | 'admin-auth';


const SYSTEM_SELLER_ID = 'system-user-driveluxe-888';
const LOCAL_STORAGE_KEY_LISTINGS = 'driveluxe_local_listings_v2'; // Updated key to avoid conflicts with old data
const LOCAL_STORAGE_KEY_USERS = 'driveluxe_local_users';
const LOCAL_STORAGE_KEY_SESSION = 'driveluxe_local_session';
const LOCAL_STORAGE_KEY_THREADS = 'driveluxe_local_chat_threads';
const LOCAL_STORAGE_KEY_MESSAGES = 'driveluxe_local_chat_messages';

const MOCK_LISTINGS: CarListing[] = [
    {
        id: '1',
        make: 'Tesla',
        model: 'Model X Plaid',
        year: 2024,
        price: 125000,
        mileage: 500,
        description: 'Brand new Plaid edition with yoke steering. Unbelievable acceleration. Full Self-Driving package included.',
        imageUrls: [
            'https://placehold.co/600x400/1e293b/a5b4fc?text=Tesla+Exterior',
            'https://placehold.co/600x400/1e293b/c7d2fe?text=Tesla+Interior',
            'https://placehold.co/600x400/1e293b/818cf8?text=Tesla+Wheel'
        ],
        isFeatured: true,
        sellerUid: SYSTEM_SELLER_ID,
        status: 'available'
    },
    {
        id: '2',
        make: 'Lucid',
        model: 'Air Grand Touring',
        year: 2023,
        price: 98000,
        mileage: 8000,
        description: 'Stunning design and record-breaking range. Fully loaded with the glass canopy roof and premium sound system.',
        imageUrls: [
            'https://placehold.co/600x400/1f2937/4c1d95?text=Lucid+Exterior',
            'https://placehold.co/600x400/1f2937/a78bfa?text=Lucid+Interior',
            'https://placehold.co/600x400/1f2937/7c3aed?text=Lucid+Profile'
        ],
        isFeatured: true,
        sellerUid: 'local-user-test',
        status: 'available'
    },
];

const generateId = () => (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : `local-${Date.now()}`;
const getStoredData = <T,>(key: string, fallback: T): T => {
    try {
        const stored = localStorage.getItem(key);
        return stored ? JSON.parse(stored) : fallback;
    } catch (error) {
        console.error(`Error reading ${key} from localStorage`, error);
        return fallback;
    }
};
const setStoredData = (key: string, data: any) => {
    try {
        localStorage.setItem(key, JSON.stringify(data));
    } catch (error) {
        console.error(`Error writing ${key} to localStorage`, error);
    }
};


const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

const useListingsState = () => {
    const [listings, setListings] = useState<CarListing[]>([]);

    const fetchListings = async () => {
        try {
            const res = await fetch(`${API_URL}/listings`);
            const data = await res.json();
            setListings(Array.isArray(data) ? data : []);
        } catch (error) {
            console.error('Error fetching listings', error);
        }
    };

    useEffect(() => {
        fetchListings();
    }, []);

    const addOrUpdateListing = async (listing: Omit<CarListing, 'id' | 'sellerUid' | 'status' | 'verificationStatus'> & { id?: string }, userId: string) => {
        try {
            if (listing.id) {
                const res = await fetch(`${API_URL}/listings/${listing.id}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(listing)
                });
                const updated = await res.json();
                setListings(prev => prev.map(l => l.id === updated.id ? updated : l));
            } else {
                const newListing = { ...listing, sellerUid: userId, status: 'available', verificationStatus: 'pending' };
                const res = await fetch(`${API_URL}/listings`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(newListing)
                });
                const created = await res.json();
                if (created.verificationStatus === 'verified' && created.status === 'available') {
                    setListings(prev => [...prev, created]);
                }
            }
        } catch (error) {
            console.error('Error saving listing', error);
        }
    };

    const deleteListing = async (id: string) => {
        try {
            await fetch(`${API_URL}/listings/${id}`, { method: 'DELETE' });
            setListings(prev => prev.filter(l => l.id !== id));
        } catch (error) {
            console.error('Error deleting listing', error);
        }
    };

    const purchaseListing = async (id: string, buyerUid: string) => {
        try {
            const res = await fetch(`${API_URL}/listings/${id}/purchase`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ buyerUid })
            });
            const updated = await res.json();
            setListings(prev => prev.map(l => l.id === id ? updated : l));
        } catch (error) {
            console.error('Error purchasing listing', error);
        }
    };

    return { listings, addOrUpdateListing, deleteListing, purchaseListing, fetchListings };
};

const useUserState = () => {
    const [currentUser, setCurrentUser] = useState<AppUser | null>(() => getStoredData(LOCAL_STORAGE_KEY_SESSION, null));

    useEffect(() => setStoredData(LOCAL_STORAGE_KEY_SESSION, currentUser), [currentUser]);

    const signUp = async (
        fullName: string,
        email: string,
        pass: string,
        mobileNumber?: string,
    ): Promise<{ success: boolean, error?: string }> => {
        try {
            const res = await fetch(`${API_URL}/users/signup`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ fullName, email, password: pass, mobileNumber })
            });
            const data = await res.json();
            if (!res.ok) return { success: false, error: data.error || 'Signup failed' };
            setCurrentUser({ uid: data.uid, email: data.email, fullName: data.fullName, mobileNumber: data.mobileNumber });
            return { success: true };
        } catch (error: any) {
            return { success: false, error: error.message };
        }
    };

    const logIn = async (email: string, pass: string): Promise<{ success: boolean, error?: string }> => {
        try {
            const res = await fetch(`${API_URL}/users/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password: pass })
            });
            const data = await res.json();
            if (!res.ok) return { success: false, error: data.error || 'Login failed' };
            setCurrentUser({ uid: data.uid, email: data.email, fullName: data.fullName, mobileNumber: data.mobileNumber });
            return { success: true };
        } catch (error: any) {
            return { success: false, error: error.message };
        }
    };

    const adminLogIn = async (email: string, pass: string): Promise<{ success: boolean, error?: string }> => {
        try {
            const res = await fetch(`${API_URL}/admin/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password: pass })
            });
            const data = await res.json();
            if (!res.ok) return { success: false, error: data.error || 'Admin login failed' };
            setCurrentUser({ uid: data.uid, email: data.email, isAdmin: data.isAdmin });
            return { success: true };
        } catch (error: any) {
            return { success: false, error: error.message };
        }
    };

    const logOut = () => setCurrentUser(null);

    const setGoogleUser = (userData: { uid: string; email: string; fullName?: string; mobileNumber?: string }) => {
        setCurrentUser({
            uid: userData.uid,
            email: userData.email,
            fullName: userData.fullName,
            mobileNumber: userData.mobileNumber,
        });
    };

    const fetchUserEmail = async (uid: string): Promise<string> => {
        try {
            const res = await fetch(`${API_URL}/users/${uid}`);
            const data = await res.json();
            return data.email || 'Unknown User';
        } catch (error) {
            return 'Unknown User';
        }
    };

    return { currentUser, signUp, logIn, adminLogIn, logOut, fetchUserEmail, setGoogleUser };
};

const useChatState = () => {
    const [threads, setThreads] = useState<ChatThread[]>([]);
    const [messages, setMessages] = useState<Record<string, ChatMessage[]>>({});

    const fetchThreads = async (userUid: string) => {
        try {
            const res = await fetch(`${API_URL}/chat/threads/${userUid}`);
            const data = await res.json();
            setThreads(Array.isArray(data) ? data : []);
        } catch (e) { console.error(e); }
    };

    const fetchMessages = async (threadId: string) => {
        try {
            const res = await fetch(`${API_URL}/chat/messages/${threadId}`);
            const data = await res.json();
            setMessages(prev => ({ ...prev, [threadId]: Array.isArray(data) ? data : [] }));
        } catch (e) { console.error(e); }
    };

    const findOrCreateChatThread = async (listing: CarListing, buyer: AppUser, sellerEmail: string): Promise<string> => {
        try {
            const res = await fetch(`${API_URL}/chat/threads`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    listingId: listing.id,
                    listingTitle: `${listing.year} ${listing.make} ${listing.model}`,
                    buyerUid: buyer.uid,
                    sellerUid: listing.sellerUid,
                    buyerEmail: buyer.email,
                    sellerEmail: sellerEmail
                })
            });
            const thread = await res.json();
            setThreads(prev => {
                if (!prev.find(t => t.id === thread.id)) return [thread, ...prev];
                return prev;
            });
            return thread.id;
        } catch (error) {
            console.error(error);
            return '';
        }
    };

    const sendMessage = async (threadId: string, text: string, senderUid: string) => {
        try {
            const res = await fetch(`${API_URL}/chat/messages`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ threadId, senderUid, text })
            });
            const newMessage = await res.json();
            setMessages(prev => ({ ...prev, [threadId]: [...(prev[threadId] || []), newMessage] }));
            setThreads(prev => prev.map(t =>
                t.id === threadId ? { ...t, lastMessage: text, lastTimestamp: newMessage.timestamp } : t
            ));
        } catch (error) {
            console.error(error);
        }
    };

    const getMessages = (threadId: string): ChatMessage[] => messages[threadId] || [];
    const getThreads = (userUid: string): ChatThread[] => {
        return threads
            .filter(t => t.buyerUid === userUid || t.sellerUid === userUid)
            .sort((a, b) => b.lastTimestamp - a.lastTimestamp);
    };
    const getThread = (threadId: string): ChatThread | undefined => threads.find(t => t.id === threadId);

    return { threads, fetchThreads, fetchMessages, findOrCreateChatThread, sendMessage, getMessages, getThreads, getThread };
};

// --- SVG Icons ---
const defaultIconStyle: React.CSSProperties = { width: '24px', height: '24px' };
const CarSvg = (props: React.SVGProps<SVGSVGElement>) => (<svg {...props} style={{ ...defaultIconStyle, ...props.style }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"> <path d="M19 17h2c.6 0 1-.4 1-1v-3c0-.8-.7-1.5-1.5-1.5h-1.34c-1.12 0-1.7-.82-1.7-1.5z" /> <path d="M2 17h2c.6 0 1-.4 1-1v-3c0-.8-.7-1.5-1.5-1.5H2" /> <path d="M14 11V5a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v6" /> <path d="M22 17H2" /> <path d="M2.5 17a2 2 0 0 0 4 0" /> <path d="M18.5 17a2 2 0 0 0 4 0" /> </svg>);
const UserSvg = (props: React.SVGProps<SVGSVGElement>) => (<svg {...props} style={{ ...defaultIconStyle, ...props.style }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"> <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" /> <circle cx="12" cy="7" r="4" /> </svg>);
const DollarSignSvg = (props: React.SVGProps<SVGSVGElement>) => (<svg {...props} style={{ ...defaultIconStyle, ...props.style }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"> <line x1="12" x2="12" y1="2" y2="22" /> <path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6" /> </svg>);
const SearchSvg = (props: React.SVGProps<SVGSVGElement>) => (<svg {...props} style={{ ...defaultIconStyle, ...props.style }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8" /><path d="m21 21-4.3-4.3" /></svg>);
const EditSvg = (props: React.SVGProps<SVGSVGElement>) => (<svg {...props} style={{ width: '16px', height: '16px', ...props.style }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z" /><path d="m15 5 4 4" /></svg>);
const TrashSvg = (props: React.SVGProps<SVGSVGElement>) => (<svg {...props} style={{ width: '16px', height: '16px', ...props.style }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6h18" /><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6" /><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2" /></svg>);
const LogOutSvg = (props: React.SVGProps<SVGSVGElement>) => (<svg {...props} style={{ ...defaultIconStyle, ...props.style }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"> <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /> <polyline points="16 17 21 12 16 7" /> <line x1="21" y1="12" x2="9" y2="12" /> </svg>);
const ArrowLeftSvg = (props: React.SVGProps<SVGSVGElement>) => (<svg {...props} style={{ ...defaultIconStyle, ...props.style }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"> <path d="m12 19-7-7 7-7" /><path d="M19 12H5" /> </svg>);
const InboxSvg = (props: React.SVGProps<SVGSVGElement>) => (<svg {...props} style={{ ...defaultIconStyle, ...props.style }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"> <path d="M22 12h-6l-2 3h-4l-2-3H2" /> <path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" /> </svg>);
const SendSvg = (props: React.SVGProps<SVGSVGElement>) => (<svg {...props} style={{ ...defaultIconStyle, ...props.style }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"> <path d="m22 2-7 20-4-9-9-4Z" /> <path d="M22 2 11 13" /> </svg>);
const LockSvg = (props: React.SVGProps<SVGSVGElement>) => (<svg {...props} style={{ ...defaultIconStyle, ...props.style }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>);
const EyeSvg = (props: React.SVGProps<SVGSVGElement>) => (<svg {...props} style={{ ...defaultIconStyle, ...props.style }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0" /><circle cx="12" cy="12" r="3" /></svg>);
const EyeOffSvg = (props: React.SVGProps<SVGSVGElement>) => (<svg {...props} style={{ ...defaultIconStyle, ...props.style }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m3 3 18 18" /><path d="M10.58 10.58a2 2 0 0 0 2.83 2.83" /><path d="M9.88 5.09A10.94 10.94 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" /><path d="M6.61 6.61A13.53 13.53 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" /></svg>);
const CheckCircleSvg = (props: React.SVGProps<SVGSVGElement>) => (<svg {...props} style={{ ...defaultIconStyle, ...props.style }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" /></svg>);
const DownloadSvg = (props: React.SVGProps<SVGSVGElement>) => (<svg {...props} style={{ ...defaultIconStyle, ...props.style }} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>);


const Header: React.FC<{
    currentView: View;
    setView: (v: View) => void;
    user: AppUser | null;
    onLogout: () => void;
}> = ({ currentView, setView, user, onLogout }) => {

    const navItems = [
        { name: 'Home', view: 'home' as View, icon: <CarSvg style={{ width: '20px', height: '20px' }} /> },
        ...(user?.isAdmin ? [{ name: 'Admin Dashboard', view: 'admin' as View, icon: <CheckCircleSvg style={{ width: '20px', height: '20px' }} /> }] : []),
        ...(!user?.isAdmin ? [
            { name: 'Listings', view: 'listings' as View, icon: <SearchSvg style={{ width: '20px', height: '20px' }} /> },
            { name: 'Sell Your Car', view: 'sell' as View, icon: <DollarSignSvg style={{ width: '20px', height: '20px' }} /> },
            ...(user ? [{ name: 'Inbox', view: 'inbox' as View, icon: <InboxSvg style={{ width: '20px', height: '20px' }} /> }] : []),
        ] : []),
    ];

    const getButtonStyle = (viewName: View): React.CSSProperties => ({
        display: 'flex', alignItems: 'center', padding: '8px 12px',
        borderRadius: '8px', transition: 'background-color 0.2s, box-shadow 0.2s',
        fontWeight: 500, border: 'none', cursor: 'pointer', whiteSpace: 'nowrap',
        backgroundColor: currentView === viewName ? '#4f46e5' : 'transparent',
        color: currentView === viewName ? '#fff' : '#d1d5db',
        boxShadow: currentView === viewName ? '0 4px 10px rgba(79, 70, 229, 0.4)' : 'none',
    });

    const logoStyle: React.CSSProperties = {
        fontSize: '30px', fontWeight: '900', cursor: 'pointer',
        background: 'linear-gradient(to right, #818cf8, #a855f7)',
        WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
    };

    return (
        <header style={{ backgroundColor: '#1f2937', boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)', borderBottom: '1px solid #4338ca50', position: 'sticky', top: 0, zIndex: 50 }}>
            <div style={{ maxWidth: '1280px', margin: '0 auto', padding: '16px 16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h1 style={logoStyle} onClick={() => setView('home')}>
                        Drive Hub
                    </h1>

                    <nav className="header-nav-desktop">
                        {navItems.map(item => (
                            <button
                                key={item.name}
                                onClick={() => setView(item.view)}
                                style={getButtonStyle(item.view)}
                            >
                                {item.icon}
                                <span style={{ marginLeft: '8px' }}>{item.name}</span>
                            </button>
                        ))}
                    </nav>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                        {user ? (
                            <>
                                <span className="header-user-email">{user.email}</span>
                                <button onClick={onLogout} style={{ padding: '8px', borderRadius: '9999px', border: 'none', cursor: 'pointer', backgroundColor: '#4b5563', color: '#fff' }}>
                                    <LogOutSvg style={{ width: '24px', height: '24px' }} />
                                </button>
                            </>
                        ) : (
                            <>
                                <button onClick={() => setView('auth')} style={getButtonStyle('auth')}>
                                    <UserSvg style={{ width: '20px', height: '20px' }} />
                                    <span style={{ marginLeft: '8px' }}>Login / Sign Up</span>
                                </button>
                                <button onClick={() => setView('admin-auth')} style={{ ...getButtonStyle('admin-auth'), border: '1px solid #f59e0b' }}>
                                    <LockSvg style={{ width: '20px', height: '20px' }} />
                                    <span style={{ marginLeft: '8px' }}>Admin Login</span>
                                </button>
                            </>
                        )}
                    </div>
                </div>
            </div>
        </header>
    );
};

/** Car Card Component */
const CarCard: React.FC<{
    car: CarListing;
    onEdit?: (car: CarListing) => void;
    onDelete?: (id: string) => void;
    isManageView?: boolean;
    currentUserId: string | null;
    onViewDetail?: (car: CarListing) => void;
    onViewInvoice?: (car: CarListing) => void;
}> = ({ car, onEdit, onDelete, isManageView = false, currentUserId, onViewDetail, onViewInvoice }) => {

    const isSeller = car.sellerUid === currentUserId;
    const isSold = car.status === 'sold';
    const coverImage = (car.imageUrls && car.imageUrls.length > 0) ? car.imageUrls[0] : `https://placehold.co/400x300/1f2937/a5b4fc?text=${car.make}+${car.model}`;

    const [isHovered, setIsHovered] = useState(false);
    const cardStyle: React.CSSProperties = {
        backgroundColor: '#1f2937', borderRadius: '12px',
        boxShadow: isHovered ? '0 20px 25px rgba(0, 0, 0, 0.7)' : '0 10px 15px rgba(0, 0, 0, 0.5)',
        overflow: 'hidden', border: '1px solid #4338ca50', transition: 'transform 0.3s, box-shadow 0.3s',
        cursor: (isManageView || isSold) ? 'default' : 'pointer',
        transform: isHovered && !isManageView && !isSold ? 'scale(1.02)' : 'scale(1)',
        position: 'relative',
        opacity: isSold ? 0.75 : 1
    };

    const handleClick = () => {
        if (!isManageView && onViewDetail && !isSold) onViewDetail(car);
    };

    return (
        <div
            style={cardStyle}
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
            onClick={handleClick}
        >
            <div style={{ position: 'absolute', top: '10px', left: '10px', backgroundColor: '#16a34a', color: 'white', padding: '5px 12px', borderRadius: '999px', fontWeight: 'bold', fontSize: '12px', zIndex: 20, boxShadow: '0 4px 6px rgba(0,0,0,0.4)' }}>
                VERIFIED
            </div>
            {isSold && (
                <div style={{ position: 'absolute', top: '10px', right: '10px', backgroundColor: '#ef4444', color: 'white', padding: '5px 15px', borderRadius: '5px', fontWeight: 'bold', zIndex: 20, transform: 'rotate(15deg)', boxShadow: '0 4px 6px rgba(0,0,0,0.5)' }}>
                    SOLD
                </div>
            )}
            <img
                src={coverImage}
                alt={`${car.make} ${car.model}`}
                style={{ width: '100%', height: '192px', objectFit: 'cover', objectPosition: 'center', filter: isSold ? 'grayscale(100%)' : 'none' }}
                onError={(e) => { e.currentTarget.src = `https://placehold.co/400x300/1f2937/a5b4fc?text=${car.make}+${car.model}`; e.currentTarget.onerror = null; }}
            />
            <div style={{ padding: '20px' }}>
                <h4 style={{ fontSize: '20px', fontWeight: 'bold', color: '#a5b4fc', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{car.make} {car.model}</h4>
                <p style={{ fontSize: '30px', fontWeight: '900', color: '#fff', margin: '8px 0' }}>₹{car.price.toLocaleString()}</p>

                <div style={{ fontSize: '14px', color: '#9ca3af', lineHeight: '1.5', marginTop: '10px' }}>
                    <p style={{ marginBottom: '4px' }}><strong>Year:</strong> {car.year}</p>
                    <p style={{ marginBottom: '4px' }}><strong>Mileage:</strong> {car.mileage.toLocaleString()} mi</p>
                </div>

                {isManageView && isSeller && (
                    <div style={{ display: 'flex', gap: '12px', marginTop: '16px', flexDirection: 'column' }}>
                        {isSold ? (
                            <button onClick={() => onViewInvoice && onViewInvoice(car)} className="btn-tertiary" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                <DownloadSvg style={{ marginRight: '8px' }} /> Download Invoice
                            </button>
                        ) : (
                            <div style={{ display: 'flex', gap: '12px' }}>
                                <button onClick={() => onEdit && onEdit(car)} className="btn-action edit">
                                    <EditSvg style={{ marginRight: '8px', color: '#fff' }} /> <span>Edit</span>
                                </button>
                                <button onClick={() => onDelete && onDelete(car.id)} className="btn-action delete">
                                    <TrashSvg style={{ marginRight: '8px', color: '#fff' }} /> <span>Delete</span>
                                </button>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};

/** Payment Modal Component */
const PaymentModal: React.FC<{
    car: CarListing;
    onClose: () => void;
    onConfirmPayment: () => void;
}> = ({ car, onClose, onConfirmPayment }) => {
    const [step, setStep] = useState<'form' | 'processing' | 'success'>('form');

    const handlePay = (e: React.FormEvent) => {
        e.preventDefault();
        setStep('processing');
        setTimeout(() => {
            setStep('success');
            setTimeout(() => {
                onConfirmPayment();
            }, 1500);
        }, 2500);
    };

    return (
        <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.8)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}>
            <div style={{ backgroundColor: '#1f2937', width: '100%', maxWidth: '500px', borderRadius: '16px', padding: '32px', border: '1px solid #4f46e5', boxShadow: '0 20px 50px rgba(0,0,0,0.8)' }}>

                {step === 'form' && (
                    <form onSubmit={handlePay}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
                            <h2 style={{ color: '#fff', fontSize: '24px', fontWeight: 'bold', margin: 0 }}>Secure Checkout</h2>
                            <LockSvg style={{ color: '#10b981' }} />
                        </div>

                        <div style={{ backgroundColor: '#374151', padding: '16px', borderRadius: '8px', marginBottom: '24px', border: '1px solid #4b5563' }}>
                            <p style={{ color: '#9ca3af', fontSize: '14px' }}>Total Amount</p>
                            <p style={{ color: '#fff', fontSize: '28px', fontWeight: '900' }}>₹{car.price.toLocaleString()}</p>
                            <p style={{ color: '#a5b4fc', fontSize: '14px' }}>{car.year} {car.make} {car.model}</p>
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                            <div>
                                <label style={{ color: '#d1d5db', fontSize: '14px', display: 'block', marginBottom: '6px' }}>Cardholder Name</label>
                                <input type="text" placeholder="John Doe" required className="input-field" style={{ width: '100%' }} />
                            </div>
                            <div>
                                <label style={{ color: '#d1d5db', fontSize: '14px', display: 'block', marginBottom: '6px' }}>Card Number</label>
                                <input type="text" placeholder="0000 0000 0000 0000" maxLength={19} required className="input-field" style={{ width: '100%', fontFamily: 'monospace' }} />
                            </div>
                            <div style={{ display: 'flex', gap: '16px' }}>
                                <div style={{ flex: 1 }}>
                                    <label style={{ color: '#d1d5db', fontSize: '14px', display: 'block', marginBottom: '6px' }}>Expiry</label>
                                    <input type="text" placeholder="MM/YY" maxLength={5} required className="input-field" style={{ width: '100%' }} />
                                </div>
                                <div style={{ flex: 1 }}>
                                    <label style={{ color: '#d1d5db', fontSize: '14px', display: 'block', marginBottom: '6px' }}>CVV</label>
                                    <input type="password" placeholder="123" maxLength={3} required className="input-field" style={{ width: '100%' }} />
                                </div>
                            </div>
                        </div>

                        <div style={{ display: 'flex', gap: '16px', marginTop: '32px' }}>
                            <button type="button" onClick={onClose} className="btn-cancel" style={{ flex: 1 }}>Cancel</button>
                            <button type="submit" className="btn-primary" style={{ flex: 2, backgroundColor: '#10b981' }}>
                                Pay ₹{car.price.toLocaleString()}
                            </button>
                        </div>
                    </form>
                )}

                {step === 'processing' && (
                    <div style={{ textAlign: 'center', padding: '40px 0' }}>
                        <div className="spinner" style={{ width: '50px', height: '50px', border: '4px solid #374151', borderTop: '4px solid #4f46e5', borderRadius: '50%', margin: '0 auto 24px', animation: 'spin 1s linear infinite' }}></div>
                        <h3 style={{ color: '#fff', fontSize: '20px' }}>Processing Payment...</h3>
                        <p style={{ color: '#9ca3af' }}>Please do not close this window.</p>
                        <style>{`@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }`}</style>
                    </div>
                )}

                {step === 'success' && (
                    <div style={{ textAlign: 'center', padding: '40px 0' }}>
                        <div style={{ backgroundColor: '#10b981', width: '60px', height: '60px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 24px' }}>
                            <CheckCircleSvg style={{ width: '40px', height: '40px', color: 'white' }} />
                        </div>
                        <h3 style={{ color: '#fff', fontSize: '24px', fontWeight: 'bold' }}>Payment Successful!</h3>
                        <p style={{ color: '#d1d5db', marginTop: '8px' }}>The car is yours. Redirecting...</p>
                    </div>
                )}
            </div>
        </div>
    );
};

/** Invoice/Bill View Component (Printable) */
const InvoiceView: React.FC<{
    car: CarListing;
    buyer: AppUser;
    onBack: () => void;
}> = ({ car, buyer, onBack }) => {

    // Fake Tax Calculation
    const taxRate = 0.08;
    const taxAmount = car.price * taxRate;
    const totalAmount = car.price + taxAmount;
    const invoiceDate = car.purchaseDate ? new Date(car.purchaseDate).toLocaleDateString() : new Date().toLocaleDateString();
    const invoiceId = `INV-${car.id.slice(0, 6).toUpperCase()}-${Date.now().toString().slice(-4)}`;

    return (
        <main style={{ minHeight: '100vh', backgroundColor: '#fff', color: '#000', padding: '40px' }}>
            {/* Screen-only controls */}
            <div className="no-print" style={{ maxWidth: '800px', margin: '0 auto 24px', display: 'flex', justifyContent: 'space-between' }}>
                <button onClick={onBack} className="btn-cancel">Back to App</button>
                <button onClick={() => window.print()} className="btn-primary">Print / Save PDF</button>
            </div>

            <div className="invoice-container" style={{ maxWidth: '800px', margin: '0 auto', border: '1px solid #ddd', padding: '40px', boxShadow: '0 0 20px rgba(0,0,0,0.05)' }}>
                {/* Header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '2px solid #4f46e5', paddingBottom: '20px', marginBottom: '30px' }}>
                    <div>
                        <h1 style={{ fontSize: '32px', color: '#4f46e5', margin: 0 }}>INVOICE</h1>
                        <p style={{ color: '#666', margin: '5px 0 0' }}>Car-Drivehub Official Receipt</p>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                        <h2 style={{ margin: 0, fontSize: '20px' }}>Car-Drivehub Ltd.</h2>
                        <p style={{ margin: '5px 0', fontSize: '14px' }}>Chitkara University</p>
                        <p style={{ margin: 0, fontSize: '14px' }}>Rajpura , Punjab India</p>
                    </div>
                </div>

                {/* Details */}
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '40px' }}>
                    <div>
                        <h3 style={{ fontSize: '16px', fontWeight: 'bold', color: '#333', borderBottom: '1px solid #eee', paddingBottom: '5px' }}>BILL TO</h3>
                        <p style={{ margin: '10px 0 5px', fontWeight: 'bold' }}>{buyer.email}</p>
                        <p style={{ margin: 0, fontSize: '14px', color: '#666' }}>User ID: {buyer.uid}</p>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                        <div style={{ marginBottom: '10px' }}>
                            <span style={{ fontWeight: 'bold', display: 'inline-block', width: '100px' }}>Invoice #:</span>
                            <span>{invoiceId}</span>
                        </div>
                        <div style={{ marginBottom: '10px' }}>
                            <span style={{ fontWeight: 'bold', display: 'inline-block', width: '100px' }}>Date:</span>
                            <span>{invoiceDate}</span>
                        </div>
                        <div>
                            <span style={{ fontWeight: 'bold', display: 'inline-block', width: '100px' }}>Status:</span>
                            <span style={{ color: '#10b981', fontWeight: 'bold' }}>PAID</span>
                        </div>
                    </div>
                </div>

                {/* Item Table */}
                <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: '30px' }}>
                    <thead>
                        <tr style={{ backgroundColor: '#f9fafb', borderBottom: '2px solid #e5e7eb' }}>
                            <th style={{ textAlign: 'left', padding: '12px', fontWeight: 'bold', color: '#374151' }}>Description</th>
                            <th style={{ textAlign: 'right', padding: '12px', fontWeight: 'bold', color: '#374151' }}>Amount</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr style={{ borderBottom: '1px solid #eee' }}>
                            <td style={{ padding: '16px 12px' }}>
                                <strong>{car.year} {car.make} {car.model}</strong>
                                <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>VIN: {car.id.toUpperCase()} | Mileage: {car.mileage} mi</div>
                            </td>
                            <td style={{ textAlign: 'right', padding: '16px 12px' }}>₹{car.price.toLocaleString()}.00</td>
                        </tr>
                        <tr style={{ borderBottom: '1px solid #eee' }}>
                            <td style={{ padding: '16px 12px', color: '#666' }}>Platform & Processing Fees (Included)</td>
                            <td style={{ textAlign: 'right', padding: '16px 12px' }}>$0.00</td>
                        </tr>
                    </tbody>
                </table>

                {/* Totals */}
                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <div style={{ width: '300px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px', padding: '0 12px' }}>
                            <span style={{ color: '#666' }}>Subtotal:</span>
                            <span>₹{car.price.toLocaleString()}.00</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px', padding: '0 12px' }}>
                            <span style={{ color: '#666' }}>Tax (8%):</span>
                            <span>₹{taxAmount.toLocaleString(undefined, { minimumFractionDigits: 2 })}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', borderTop: '2px solid #333', padding: '12px', fontSize: '18px', fontWeight: 'bold', backgroundColor: '#f3f4f6', marginTop: '10px' }}>
                            <span>Total:</span>
                            <span>₹{totalAmount.toLocaleString(undefined, { minimumFractionDigits: 2 })}</span>
                        </div>
                    </div>
                </div>

                {/* Footer */}
                <div style={{ marginTop: '60px', textAlign: 'center', fontSize: '12px', color: '#9ca3af', borderTop: '1px solid #eee', paddingTop: '20px' }}>
                    <p>Thank you for your business!</p>
                    <p>For any inquiries, please contact support@car-drivehub.com</p>
                </div>
            </div>

            <style>{`
                @media print {
                    .no-print { display: none !important; }
                    body, main { background-color: #fff; padding: 0; margin: 0; }
                    .invoice-container { box-shadow: none; border: none; }
                }
            `}</style>
        </main>
    );
};


const HomeView: React.FC<{
    setView: (v: View) => void;
    recentListings: CarListing[];
    allListings: CarListing[];
    currentUserId: string | null;
    onViewDetail: (car: CarListing) => void;
}> = ({ setView, recentListings, allListings, currentUserId, onViewDetail }) => {

    const [searchParams, setSearchParams] = useState({ make: '', year: '', priceRange: '' });
    const [isSearchActive, setIsSearchActive] = useState(false);
    const handleSearchChange = (e: React.ChangeEvent<HTMLSelectElement | HTMLInputElement>) => {
        setSearchParams({ ...searchParams, [e.target.name]: e.target.value });
    };

    const handleSearchSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        // Activate in-place search if any filter is set
        if (searchParams.make || searchParams.year || searchParams.priceRange) {
            setIsSearchActive(true);
        }
    };

    const handleClearSearch = () => {
        setSearchParams({ make: '', year: '', priceRange: '' });
        setIsSearchActive(false);
    };

    // Filter listings based on search params
    const searchResults = useMemo(() => {
        if (!isSearchActive) return [];
        const activeListings = allListings.filter(l => l.status !== 'sold');
        return activeListings.filter(car => {
            // Make filter
            if (searchParams.make) {
                const term = searchParams.make.toLowerCase();
                if (!car.make.toLowerCase().includes(term) && !car.model.toLowerCase().includes(term)) {
                    return false;
                }
            }
            // Year filter
            if (searchParams.year) {
                if (searchParams.year === '2023+' && car.year < 2023) return false;
                if (searchParams.year === '2020-2022' && (car.year < 2020 || car.year > 2022)) return false;
                if (searchParams.year === 'Pre-2020' && car.year >= 2020) return false;
            }
            // Price filter
            if (searchParams.priceRange) {
                if (searchParams.priceRange === '<500000' && car.price >= 500000) return false;
                if (searchParams.priceRange === '500000-1000000' && (car.price < 500000 || car.price > 1000000)) return false;
                if (searchParams.priceRange === '>1000000' && car.price <= 1000000) return false;
            }
            return true;
        });
    }, [isSearchActive, allListings, searchParams]);

    const heroStyle: React.CSSProperties = {
        position: 'relative', overflow: 'hidden', borderRadius: '16px',
        boxShadow: '0 20px 25px rgba(0, 0, 0, 0.4)', padding: '48px', marginBottom: '48px',
        backgroundColor: 'rgba(31, 41, 55, 0.7)', border: '1px solid #4338ca50',
    };
    const searchFormStyle: React.CSSProperties = {
        maxWidth: '900px', margin: '0 auto', backgroundColor: 'rgba(17, 24, 39, 0.8)',
        padding: '24px', borderRadius: '12px', boxShadow: 'inset 0 2px 4px rgba(0, 0, 0, 0.6)',
        border: '1px solid #4f46e550', backdropFilter: 'blur(4px)',
    };

    return (
        <main style={{ minHeight: '80vh', backgroundColor: '#111827', color: '#fff', paddingTop: '32px' }}>
            <div style={{ maxWidth: '1280px', margin: '0 auto', padding: '0 16px' }}>
                <div style={heroStyle}>
                    <div style={{ position: 'absolute', inset: 0, backgroundImage: "url(https://images.unsplash.com/photo-1553440569-bcc63803a83d?q=80&w=2940&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D)", backgroundSize: 'cover', backgroundPosition: 'center', opacity: 0.3 }}></div>
                    <div style={{ position: 'relative', zIndex: 10, textAlign: 'center' }}>
                        <h2 style={{ fontSize: '40px', fontWeight: '900', marginBottom: '16px', color: '#fff', textShadow: '0 2px 4px rgba(0, 0, 0, 0.8)' }}>
                            Find Your Next Cyber-Luxe Ride
                        </h2>
                        <p style={{ fontSize: '20px', color: '#a5b4fc', marginBottom: '32px' }}>
                            Discover high-performance vehicles, engineered for tomorrow.
                        </p>
                        <form onSubmit={handleSearchSubmit} style={searchFormStyle}>
                            <div className="home-search-grid">
                                <input type="text" name="make" placeholder="Make (e.g., Tesla, Lucid)" value={searchParams.make} onChange={handleSearchChange} className="input-field" />
                                <select name="year" value={searchParams.year} onChange={handleSearchChange} className="input-field" >
                                    <option value="">Year</option>
                                    <option value="2023+">2023+</option>
                                    <option value="2020-2022">2020-2022</option>
                                    <option value="Pre-2020">Pre-2020</option>
                                </select>
                                <select name="priceRange" value={searchParams.priceRange} onChange={handleSearchChange} className="input-field" >
                                    <option value="">Price Range</option>
                                    <option value="<500000">Below ₹5 Lakhs</option>
                                    <option value="500000-1000000">₹5L - ₹10 Lakhs</option>
                                    <option value=">1000000">Over ₹10 Lakhs</option>
                                </select>
                                <button type="submit" className="btn-primary" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                    <SearchSvg style={{ width: '20px', height: '20px', marginRight: '8px', color: '#fff' }} />
                                    <span>Search Cars</span>
                                </button>
                            </div>
                        </form>
                    </div>
                </div>

                {/* Search Results Section (shown when search is active) */}
                {isSearchActive ? (
                    <>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
                            <h3 style={{ fontSize: '36px', fontWeight: 'bold', color: '#818cf8', margin: 0 }}>
                                Search Results <span style={{ fontSize: '18px', color: '#9ca3af', fontWeight: '400' }}>({searchResults.length} found)</span>
                            </h3>
                            <button onClick={handleClearSearch} className="btn-cancel" style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 20px' }}>
                                ✕ Clear Search
                            </button>
                        </div>
                        <div className="home-listings-grid">
                            {searchResults.length > 0 ? searchResults.map(car => (
                                <CarCard key={car.id} car={car} currentUserId={currentUserId} onViewDetail={onViewDetail} />
                            )) : (
                                <div style={{ gridColumn: '1 / -1', textAlign: 'center', padding: '60px 20px' }}>
                                    <div style={{ fontSize: '60px', marginBottom: '16px' }}>🔍</div>
                                    <p style={{ color: '#9ca3af', fontSize: '18px', marginBottom: '8px' }}>No cars match your search criteria.</p>
                                    <p style={{ color: '#6b7280', fontSize: '14px' }}>Try adjusting your filters or clear the search.</p>
                                </div>
                            )}
                        </div>
                    </>
                ) : (
                    <>
                        <h3 style={{ fontSize: '36px', fontWeight: 'bold', textAlign: 'center', color: '#818cf8', marginBottom: '24px' }}>Recent Cars</h3>
                        <div className="home-listings-grid">
                            {recentListings.length > 0 ? recentListings.map(car => (
                                <CarCard key={car.id} car={car} currentUserId={currentUserId} onViewDetail={onViewDetail} />
                            )) : <p style={{ color: '#9ca3af', textAlign: 'center', width: '100%' }}>No listings yet.</p>}
                        </div>
                    </>
                )}

                <div style={{ textAlign: 'center', marginTop: '48px', marginBottom: '32px' }}>
                    <button onClick={() => setView('listings')} className="btn-secondary" style={{ padding: '12px 24px', fontSize: '18px' }}>
                        View All Listings
                    </button>
                </div>
            </div>
        </main>
    );
};

const UserDashboardView: React.FC<{
    user: AppUser;
    setView: (v: View) => void;
    onViewDetail: (car: CarListing) => void;
    onLogout: () => void;
}> = ({ user, setView, onViewDetail, onLogout }) => {

    return (
        <main style={{ minHeight: '80vh', backgroundColor: '#111827', color: '#fff', paddingTop: '32px' }}>
            <div style={{ maxWidth: '1280px', margin: '0 auto', padding: '0 16px' }}>
                <div style={{ backgroundColor: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', padding: '40px', borderRadius: '16px', marginBottom: '48px', boxShadow: '0 20px 25px rgba(0, 0, 0, 0.4)' }}>
                    <h1 style={{ fontSize: '40px', fontWeight: '900', color: '#fff', marginBottom: '8px' }}>Welcome, {(user.fullName && user.fullName.trim()) ? user.fullName.split(' ')[0] : user.email}</h1>
                    <p style={{ fontSize: '18px', color: '#e9ecef', margin: 0 }}>Your personal dashboard</p>
                </div>

                <h2 style={{ fontSize: '28px', fontWeight: 'bold', color: '#a5b4fc', marginBottom: '24px' }}>Quick Actions</h2>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '24px', marginBottom: '48px' }}>
                    <div style={{ backgroundColor: '#1f2937', padding: '32px', borderRadius: '12px', border: '1px solid #4338ca50', textAlign: 'center', cursor: 'pointer', transition: 'all 0.3s', transform: 'scale(1)' }}
                        onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.transform = 'scale(1.05)'; }}
                        onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.transform = 'scale(1)'; }}
                        onClick={() => setView('listings')}>
                        <div style={{ fontSize: '40px', marginBottom: '16px' }}>📋</div>
                        <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#fff', marginBottom: '8px' }}>Browse Listings</h3>
                        <p style={{ color: '#9ca3af', fontSize: '14px' }}>View all available cars</p>
                    </div>
                    <div style={{ backgroundColor: '#1f2937', padding: '32px', borderRadius: '12px', border: '1px solid #4338ca50', textAlign: 'center', cursor: 'pointer', transition: 'all 0.3s', transform: 'scale(1)' }}
                        onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.transform = 'scale(1.05)'; }}
                        onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.transform = 'scale(1)'; }}
                        onClick={() => setView('sell')}>
                        <div style={{ fontSize: '40px', marginBottom: '16px' }}>🚗</div>
                        <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#fff', marginBottom: '8px' }}>Sell Your Car</h3>
                        <p style={{ color: '#9ca3af', fontSize: '14px' }}>List a new vehicle</p>
                    </div>

                    <div style={{ backgroundColor: '#1f2937', padding: '32px', borderRadius: '12px', border: '1px solid #4338ca50', textAlign: 'center', cursor: 'pointer', transition: 'all 0.3s', transform: 'scale(1)' }}
                        onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.transform = 'scale(1.05)'; }}
                        onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.transform = 'scale(1)'; }}
                        onClick={() => setView('inbox')}>
                        <div style={{ fontSize: '40px', marginBottom: '16px' }}>💬</div>
                        <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#fff', marginBottom: '8px' }}>Messages</h3>
                        <p style={{ color: '#9ca3af', fontSize: '14px' }}>View your inbox</p>
                    </div>
                </div>

                <div style={{ backgroundColor: '#1f2937', padding: '32px', borderRadius: '12px', border: '1px solid #4338ca50' }}>
                    <h2 style={{ fontSize: '24px', fontWeight: 'bold', color: '#a5b4fc', marginBottom: '24px' }}>Account Information</h2>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '24px' }}>
                        <div>
                            <p style={{ color: '#9ca3af', fontSize: '14px', marginBottom: '8px' }}>Email</p>
                            <p style={{ color: '#fff', fontSize: '16px', fontWeight: '600', fontFamily: 'monospace' }}>{user.email}</p>
                        </div>
                        <div>
                            <p style={{ color: '#9ca3af', fontSize: '14px', marginBottom: '8px' }}>User ID</p>
                            <p style={{ color: '#fff', fontSize: '16px', fontWeight: '600', fontFamily: 'monospace' }}>{user.uid}</p>
                        </div>
                        <div>
                            <p style={{ color: '#9ca3af', fontSize: '14px', marginBottom: '8px' }}>Account Type</p>
                            <p style={{ color: '#fff', fontSize: '16px', fontWeight: '600' }}>Regular User</p>
                        </div>
                    </div>
                    <button onClick={onLogout} style={{ marginTop: '24px', padding: '12px 24px', backgroundColor: '#dc2626', color: '#fff', borderRadius: '8px', border: 'none', cursor: 'pointer', fontWeight: '600' }}>
                        Logout
                    </button>
                </div>
            </div>
        </main>
    );
};

const ListingsView: React.FC<{
    listings: CarListing[];
    currentUserId: string | null;
    onViewDetail: (car: CarListing) => void;
}> = ({ listings, currentUserId, onViewDetail }) => {
    const [searchTerm, setSearchTerm] = useState('');

    const activeListings = useMemo(() => listings.filter(l => l.status !== 'sold'), [listings]);

    const filteredListings = useMemo(() => {
        if (!searchTerm) return activeListings;
        const lowerSearchTerm = searchTerm.toLowerCase();
        return activeListings.filter(car =>
            car.make.toLowerCase().includes(lowerSearchTerm) ||
            car.model.toLowerCase().includes(lowerSearchTerm) ||
            car.year.toString().includes(lowerSearchTerm)
        );
    }, [activeListings, searchTerm]);

    return (
        <main style={{ minHeight: '80vh', backgroundColor: '#111827', color: '#fff', padding: '48px 0' }}>
            <div style={{ maxWidth: '1280px', margin: '0 auto', padding: '0 16px' }}>
                <h2 style={{ fontSize: '36px', fontWeight: '900', textAlign: 'center', color: '#818cf8', marginBottom: '32px' }}>All Available Listings</h2>

                <div style={{ maxWidth: '600px', margin: '0 auto 40px' }}>
                    <div style={{ position: 'relative' }}>
                        <input
                            type="text"
                            placeholder="Search by Make, Model, or Year..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            style={{ width: '100%', padding: '16px 16px 16px 48px', backgroundColor: '#1f2937', border: '1px solid #4f46e5', borderRadius: '12px', color: '#fff', outline: 'none' }}
                        />
                        <SearchSvg style={{ position: 'absolute', left: '16px', top: '50%', transform: 'translateY(-50%)', width: '20px', height: '20px', color: '#a5b4fc' }} />
                    </div>
                </div>

                {filteredListings.length === 0 ? (
                    <p style={{ textAlign: 'center', color: '#9ca3af', padding: '48px 0' }}>
                        {activeListings.length === 0
                            ? "There are no active listings at the moment."
                            : `No results found for "${searchTerm}".`
                        }
                    </p>
                ) : (
                    <div className="listings-grid">
                        {filteredListings.map(car => (
                            <CarCard
                                key={car.id}
                                car={car}
                                currentUserId={currentUserId}
                                onViewDetail={onViewDetail}
                            />
                        ))}
                    </div>
                )}
            </div>
        </main>
    );
};


const CarDetailView: React.FC<{
    car: CarListing;
    onBack: () => void;
    currentUser: AppUser | null;
    onContactSeller: (listing: CarListing, buyer: AppUser) => void;
    onBuyNow: (listing: CarListing) => void;
}> = ({ car, onBack, currentUser, onContactSeller, onBuyNow }) => {

    const [selectedImageIndex, setSelectedImageIndex] = useState(0);
    const fallbackImage = `https://placehold.co/800x600/1f2937/a5b4fc?text=${car.make}+${car.model}`;
    const images = (car.imageUrls && car.imageUrls.length > 0) ? car.imageUrls : [fallbackImage];
    const mainImage = images[selectedImageIndex] || fallbackImage;
    const isSeller = currentUser?.uid === car.sellerUid;

    return (
        <main style={{ minHeight: '80vh', backgroundColor: '#111827', color: '#fff', padding: '48px 0' }}>
            <div style={{ maxWidth: '1024px', margin: '0 auto', padding: '0 16px' }}>

                <button onClick={onBack} className="btn-primary" style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '24px', backgroundColor: '#374151' }}>
                    <ArrowLeftSvg style={{ width: '20px', height: '20px' }} /> Back to Listings
                </button>

                <div className="detail-grid-container">
                    <div style={{ backgroundColor: '#1f2937', padding: '24px', borderRadius: '12px', border: '1px solid #4338ca50' }}>
                        <img src={mainImage} alt="Main car view" style={{ width: '100%', height: 'auto', maxHeight: '500px', objectFit: 'cover', borderRadius: '8px', border: '1px solid #4b5563' }} onError={(e) => { e.currentTarget.src = fallbackImage; e.currentTarget.onerror = null; }} />
                        <div style={{ display: 'flex', gap: '12px', marginTop: '16px', overflowX: 'auto', paddingBottom: '8px' }}>
                            {images.map((url, index) => (
                                <img key={index} src={url} alt={`Thumbnail ${index + 1}`} onClick={() => setSelectedImageIndex(index)} style={{ width: '100px', height: '75px', objectFit: 'cover', borderRadius: '6px', cursor: 'pointer', border: index === selectedImageIndex ? '3px solid #818cf8' : '3px solid transparent', opacity: index === selectedImageIndex ? 1 : 0.7, transition: 'all 0.2s' }} />
                            ))}
                        </div>
                    </div>

                    <div style={{ backgroundColor: '#1f2937', padding: '32px', borderRadius: '12px', border: '1px solid #4338ca50' }}>
                        <h2 style={{ fontSize: '32px', fontWeight: '900', color: '#a5b4fc', margin: 0 }}>{car.make} {car.model}</h2>
                        <p style={{ fontSize: '18px', fontWeight: 500, color: '#d1d5db', marginBottom: '24px' }}>{car.year}</p>
                        <p style={{ fontSize: '48px', fontWeight: '900', color: '#fff', margin: '0 0 24px 0' }}>₹{car.price.toLocaleString()}</p>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', fontSize: '16px', color: '#9ca3af', marginBottom: '24px' }}>
                            <div><strong style={{ color: '#d1d5db' }}>Mileage</strong><p>{car.mileage.toLocaleString()} mi</p></div>
                            <div><strong style={{ color: '#d1d5db' }}>Seller ID</strong><p style={{ fontFamily: 'monospace', fontSize: '14px', color: '#818cf8' }}>{car.sellerUid}</p></div>
                        </div>

                        <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#fff', borderBottom: '1px solid #4b5563', paddingBottom: '8px', marginBottom: '16px' }}>Description</h3>
                        <p style={{ color: '#d1d5db', lineHeight: 1.6 }}>{car.description}</p>

                        <div style={{ marginTop: '40px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                            {/* Buy Now Button */}
                            <button
                                onClick={() => onBuyNow(car)}
                                disabled={isSeller || !currentUser}
                                className="btn-primary"
                                style={{
                                    padding: '16px', fontSize: '20px', backgroundColor: '#10b981',
                                    boxShadow: '0 0 15px rgba(16, 185, 129, 0.4)',
                                    opacity: (isSeller || !currentUser) ? 0.5 : 1, cursor: (isSeller || !currentUser) ? 'not-allowed' : 'pointer'
                                }}
                            >
                                {isSeller ? "You Own This Car" : (!currentUser ? "Log in to Buy" : "Buy Now - Secure Checkout")}
                            </button>

                            <button
                                onClick={() => currentUser && !isSeller && onContactSeller(car, currentUser)}
                                disabled={!currentUser || isSeller}
                                className="btn-secondary"
                                style={{ padding: '16px', fontSize: '18px', opacity: (!currentUser || isSeller) ? 0.5 : 1, cursor: (!currentUser || isSeller) ? 'not-allowed' : 'pointer' }}
                            >
                                Contact Seller
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    );
};


const GoogleSvg = (props: React.SVGProps<SVGSVGElement>) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" style={{ width: '20px', height: '20px', ...props.style }}>
        <path fill="#FFC107" d="M43.611,20.083H42V20H24v8h11.303c-1.649,4.657-6.08,8-11.303,8c-6.627,0-12-5.373-12-12c0-6.627,5.373-12,12-12c3.059,0,5.842,1.154,7.961,3.039l5.657-5.657C34.046,6.053,29.268,4,24,4C12.955,4,4,12.955,4,24c0,11.045,8.955,20,20,20c11.045,0,20-8.955,20-20C44,22.659,43.862,21.35,43.611,20.083z" />
        <path fill="#FF3D00" d="M6.306,14.691l6.571,4.819C14.655,15.108,18.961,12,24,12c3.059,0,5.842,1.154,7.961,3.039l5.657-5.657C34.046,6.053,29.268,4,24,4C16.318,4,9.656,8.337,6.306,14.691z" />
        <path fill="#4CAF50" d="M24,44c5.166,0,9.86-1.977,13.409-5.192l-6.19-5.238C29.211,35.091,26.715,36,24,36c-5.202,0-9.619-3.317-11.283-7.946l-6.522,5.025C9.505,39.556,16.227,44,24,44z" />
        <path fill="#1976D2" d="M43.611,20.083H42V20H24v8h11.303c-0.792,2.237-2.231,4.166-4.087,5.571c0.001-0.001,0.002-0.001,0.003-0.002l6.19,5.238C36.971,39.205,44,34,44,24C44,22.659,43.862,21.35,43.611,20.083z" />
    </svg>
);

const AuthView: React.FC<{
    onLogin: () => void;
    onSignUp: (fullName: string, email: string, pass: string, mobileNumber?: string) => Promise<{ success: boolean, error?: string }>;
    onLoginAttempt: (email: string, pass: string) => Promise<{ success: boolean, error?: string }>;
    setView: (v: View) => void;
}> = ({ onLogin, onSignUp, onLoginAttempt, setView }) => {

    const [isLoginView, setIsLoginView] = useState(true);
    const [fullName, setFullName] = useState('');
    const [email, setEmail] = useState('');
    const [mobileNumber, setMobileNumber] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);

        if (!isLoginView) {
            if (!fullName.trim()) {
                setError('Full name is required.');
                return;
            }
            if (password.length < 6) {
                setError('Password must be at least 6 characters.');
                return;
            }
            if (password !== confirmPassword) {
                setError('Password and confirm password must match.');
                return;
            }
            const cleanedMobile = mobileNumber.trim();
            if (cleanedMobile && !/^[6-9]\d{9}$/.test(cleanedMobile)) {
                setError('Mobile number must be 10 digits and start with 6, 7, 8, or 9.');
                return;
            }
        }

        const result = isLoginView
            ? await onLoginAttempt(email, password)
            : await onSignUp(fullName.trim(), email, password, mobileNumber.trim() || undefined);
        if (!result.success) setError(result.error || 'Authentication failed.');
    };

    const handleGoogleLogin = () => {
        // Redirect to backend Google OAuth endpoint
        window.location.href = `${API_URL.replace('/api', '')}/api/auth/google`;
    };

    return (
        <main style={{ minHeight: '80vh', backgroundColor: '#111827', color: '#fff', padding: '48px 16px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ maxWidth: '448px', width: '100%', backgroundColor: '#1f2937', padding: '40px', borderRadius: '12px', boxShadow: '0 20px 25px rgba(0, 0, 0, 0.5)', border: '1px solid #9333ea50' }}>
                <h2 style={{ fontSize: '28px', fontWeight: 'bold', color: '#c084fc', marginBottom: '8px', textAlign: 'center' }}>{isLoginView ? 'Welcome Back' : 'Create Account'}</h2>
                {error && <div style={{ padding: '12px', borderRadius: '8px', backgroundColor: '#ef4444', color: '#fff', marginBottom: '16px', textAlign: 'center' }}>{error}</div>}

                {/* Google Sign-In Button */}
                <button
                    onClick={handleGoogleLogin}
                    style={{
                        width: '100%', padding: '12px 16px', borderRadius: '8px', border: '1px solid #4b5563',
                        backgroundColor: '#fff', color: '#374151', fontWeight: '600', fontSize: '15px',
                        cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
                        gap: '12px', marginBottom: '20px', transition: 'all 0.2s',
                        boxShadow: '0 1px 3px rgba(0,0,0,0.2)',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.backgroundColor = '#f3f4f6'; e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.3)'; }}
                    onMouseLeave={e => { e.currentTarget.style.backgroundColor = '#fff'; e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.2)'; }}
                >
                    <GoogleSvg />
                    <span>{isLoginView ? 'Sign in with Google' : 'Sign up with Google'}</span>
                </button>

                {/* Divider */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '20px' }}>
                    <div style={{ flex: 1, height: '1px', backgroundColor: '#4b5563' }}></div>
                    <span style={{ color: '#9ca3af', fontSize: '13px', textTransform: 'uppercase', letterSpacing: '1px' }}>or</span>
                    <div style={{ flex: 1, height: '1px', backgroundColor: '#4b5563' }}></div>
                </div>

                <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    {!isLoginView && (
                        <input type="text" placeholder="Full Name" value={fullName} onChange={(e) => setFullName(e.target.value)} required className="input-field" />
                    )}
                    <input type="email" placeholder="Email Address" value={email} onChange={(e) => setEmail(e.target.value)} required className="input-field" />
                    {!isLoginView && (
                        <input
                            type="tel"
                            placeholder="Mobile Number (Optional)"
                            value={mobileNumber}
                            onChange={(e) => setMobileNumber(e.target.value.replace(/\D/g, '').slice(0, 10))}
                            className="input-field"
                        />
                    )}
                    <div style={{ position: 'relative' }}>
                        <input
                            type={showPassword ? 'text' : 'password'}
                            placeholder={isLoginView ? 'Password' : 'Password (Min 6 Characters)'}
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            className="input-field"
                            style={{ width: '100%', paddingRight: '44px' }}
                        />
                        <button
                            type="button"
                            onClick={() => setShowPassword(prev => !prev)}
                            aria-label={showPassword ? 'Hide password' : 'Show password'}
                            style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'transparent', color: '#c4b5fd', padding: '0', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                        >
                            {showPassword ? <EyeOffSvg style={{ width: '18px', height: '18px' }} /> : <EyeSvg style={{ width: '18px', height: '18px' }} />}
                        </button>
                    </div>
                    {!isLoginView && (
                        <div style={{ position: 'relative' }}>
                            <input
                                type={showConfirmPassword ? 'text' : 'password'}
                                placeholder="Confirm Password"
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                required
                                className="input-field"
                                style={{ width: '100%', paddingRight: '44px' }}
                            />
                            <button
                                type="button"
                                onClick={() => setShowConfirmPassword(prev => !prev)}
                                aria-label={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'}
                                style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'transparent', color: '#c4b5fd', padding: '0', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                            >
                                {showConfirmPassword ? <EyeOffSvg style={{ width: '18px', height: '18px' }} /> : <EyeSvg style={{ width: '18px', height: '18px' }} />}
                            </button>
                        </div>
                    )}
                    <button type="submit" className="btn-primary" style={{ backgroundColor: '#9333ea' }}>{isLoginView ? 'Log In' : 'Sign Up'}</button>
                </form>
                <div style={{ textAlign: 'center', marginTop: '24px' }}>
                    <button
                        onClick={() => {
                            setIsLoginView(!isLoginView);
                            setError(null);
                            setFullName('');
                            setEmail('');
                            setMobileNumber('');
                            setPassword('');
                            setConfirmPassword('');
                            setShowPassword(false);
                            setShowConfirmPassword(false);
                        }}
                        style={{ color: '#c084fc', background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline' }}
                    >
                        {isLoginView ? 'Need an account? Sign Up' : 'Have an account? Log In'}
                    </button>
                </div>
            </div>
        </main>
    );
};

const AdminAuthView: React.FC<{
    onAdminLogin: (email: string, pass: string) => Promise<{ success: boolean, error?: string }>;
    setView: (v: View) => void;
}> = ({ onAdminLogin, setView }) => {

    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);
        const result = await onAdminLogin(email, password);
        if (result.success) {
            setView('admin');
        } else {
            setError(result.error || 'Admin authentication failed.');
        }
    };

    return (
        <main style={{ minHeight: '80vh', backgroundColor: '#111827', color: '#fff', padding: '48px 16px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ maxWidth: '448px', width: '100%', backgroundColor: '#1f2937', padding: '40px', borderRadius: '12px', boxShadow: '0 20px 25px rgba(0, 0, 0, 0.5)', border: '1px solid #f59e0b50' }}>
                <h2 style={{ fontSize: '28px', fontWeight: 'bold', color: '#f59e0b', marginBottom: '8px', textAlign: 'center' }}>Admin Login</h2>
                <p style={{ textAlign: 'center', color: '#9ca3af', marginBottom: '24px' }}>Enter admin credentials to access the admin panel</p>
                {error && <div style={{ padding: '12px', borderRadius: '8px', backgroundColor: '#ef4444', color: '#fff', marginBottom: '16px', textAlign: 'center' }}>{error}</div>}
                <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <input type="email" placeholder="Admin Email" value={email} onChange={(e) => setEmail(e.target.value)} required className="input-field" />
                    <div style={{ position: 'relative' }}>
                        <input
                            type={showPassword ? 'text' : 'password'}
                            placeholder="Admin Password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            className="input-field"
                            style={{ width: '100%', paddingRight: '44px' }}
                        />
                        <button
                            type="button"
                            onClick={() => setShowPassword(prev => !prev)}
                            aria-label={showPassword ? 'Hide admin password' : 'Show admin password'}
                            style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'transparent', color: '#fbbf24', padding: '0', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                        >
                            {showPassword ? <EyeOffSvg style={{ width: '18px', height: '18px' }} /> : <EyeSvg style={{ width: '18px', height: '18px' }} />}
                        </button>
                    </div>
                    <button type="submit" className="btn-primary" style={{ backgroundColor: '#f59e0b' }}>Login as Admin</button>
                </form>
                <div style={{ textAlign: 'center', marginTop: '24px' }}>
                    <button onClick={() => setView('home')} style={{ color: '#f59e0b', background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline' }}>Back to Home</button>
                </div>
            </div>
        </main>
    );
};

const InboxView: React.FC<{ threads: ChatThread[]; currentUser: AppUser; onViewThread: (id: string) => void; }> = ({ threads, currentUser, onViewThread }) => (
    <main style={{ minHeight: '80vh', backgroundColor: '#111827', color: '#fff', padding: '48px 0' }}>
        <div style={{ maxWidth: '1024px', margin: '0 auto', padding: '0 16px' }}>
            <h2 style={{ fontSize: '36px', fontWeight: '900', textAlign: 'center', color: '#818cf8', marginBottom: '32px' }}>My Inbox</h2>
            <div style={{ backgroundColor: '#1f2937', borderRadius: '12px', border: '1px solid #4338ca50', overflow: 'hidden' }}>
                {threads.length === 0 ? <p style={{ textAlign: 'center', color: '#9ca3af', padding: '48px' }}>No messages yet.</p> : (
                    <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
                        {threads.map(thread => (
                            <li key={thread.id} onClick={() => onViewThread(thread.id)} style={{ padding: '20px', cursor: 'pointer', borderBottom: '1px solid #374151' }} className="inbox-item">
                                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                    <span style={{ fontWeight: 'bold', color: '#a5b4fc' }}>{thread.listingTitle}</span>
                                    <span style={{ fontSize: '12px', color: '#9ca3af' }}>{new Date(thread.lastTimestamp).toLocaleTimeString()}</span>
                                </div>
                                <p style={{ color: '#d1d5db', fontSize: '14px', margin: '4px 0' }}>{thread.lastMessage}</p>
                            </li>
                        ))}
                    </ul>
                )}
            </div>
        </div>
    </main>
);

const ChatView: React.FC<{ thread: ChatThread | undefined; messages: ChatMessage[]; currentUser: AppUser; onSendMessage: (text: string) => void; onBack: () => void; }> = ({ thread, messages, currentUser, onSendMessage, onBack }) => {
    const [msg, setMsg] = useState('');
    const bottomRef = useRef<HTMLDivElement>(null);
    useEffect(() => bottomRef.current?.scrollIntoView({ behavior: 'smooth' }), [messages]);

    if (!thread) return null;

    return (
        <main style={{ minHeight: '80vh', backgroundColor: '#111827', color: '#fff', padding: '24px 0' }}>
            <div style={{ maxWidth: '800px', margin: '0 auto', padding: '0 16px', height: '80vh', display: 'flex', flexDirection: 'column' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '16px' }}>
                    <button onClick={onBack} className="btn-primary" style={{ padding: '8px' }}><ArrowLeftSvg style={{ width: '20px' }} /></button>
                    <h2 style={{ margin: 0, fontSize: '20px' }}>{thread.listingTitle}</h2>
                </div>
                <div style={{ flex: 1, backgroundColor: '#1f2937', borderRadius: '12px', padding: '20px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    {messages.map(m => (
                        <div key={m.id} style={{ alignSelf: m.senderUid === currentUser.uid ? 'flex-end' : 'flex-start', backgroundColor: m.senderUid === currentUser.uid ? '#4f46e5' : '#374151', padding: '10px 16px', borderRadius: '16px', maxWidth: '75%' }}>
                            <p style={{ margin: 0 }}>{m.text}</p>
                        </div>
                    ))}
                    <div ref={bottomRef} />
                </div>
                <form onSubmit={(e) => { e.preventDefault(); if (msg.trim()) { onSendMessage(msg); setMsg(''); } }} style={{ marginTop: '16px', display: 'flex', gap: '12px' }}>
                    <input type="text" value={msg} onChange={e => setMsg(e.target.value)} className="input-field" style={{ flex: 1 }} placeholder="Type a message..." />
                    <button type="submit" className="btn-primary"><SendSvg /></button>
                </form>
            </div>
        </main>
    );
};

const App = () => {
    const [view, setView] = useState<View>('home');
    const [selectedCar, setSelectedCar] = useState<CarListing | null>(null);
    const [activeThreadId, setActiveThreadId] = useState<string | null>(null);
    const [showPaymentModal, setShowPaymentModal] = useState(false);
    const [itemToBuy, setItemToBuy] = useState<CarListing | null>(null);

    const { currentUser, signUp, logIn, adminLogIn, logOut, fetchUserEmail, setGoogleUser } = useUserState();
    const { listings, addOrUpdateListing, deleteListing, purchaseListing, fetchListings } = useListingsState();
    const { fetchThreads, fetchMessages, findOrCreateChatThread, sendMessage, getMessages, getThreads, getThread } = useChatState();

    // Handle Google OAuth callback
    useEffect(() => {
        const urlParams = new URLSearchParams(window.location.search);
        const googleAuthData = urlParams.get('google_auth');
        const authFailed = urlParams.get('auth');

        if (googleAuthData) {
            try {
                const userData = JSON.parse(decodeURIComponent(googleAuthData));
                setGoogleUser(userData);
                setView('user-dashboard');
            } catch (e) {
                console.error('Failed to parse Google auth data', e);
            }
            // Clean URL
            window.history.replaceState({}, document.title, window.location.pathname);
        } else if (authFailed === 'failed') {
            console.error('Google authentication failed');
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }, []);

    useEffect(() => {
        if (currentUser) {
            fetchThreads(currentUser.uid);
        }
    }, [currentUser]);

    useEffect(() => {
        if (view === 'home' || view === 'listings') {
            fetchListings();
        }
    }, [view]);

    const recentListings = useMemo(() => {
        return [...listings]
            .filter((l) => l.status !== 'sold')
            .sort((a, b) => {
                const aTime = a.createdAt ? new Date(a.createdAt).getTime() : 0;
                const bTime = b.createdAt ? new Date(b.createdAt).getTime() : 0;
                return bTime - aTime;
            })
            .slice(0, 5);
    }, [listings]);

    const handleLogout = () => { logOut(); setView('home'); };
    const handleViewDetail = (car: CarListing) => { setSelectedCar(car); setView('detail'); window.scrollTo(0, 0); };

    const handleContactSeller = async (listing: CarListing, buyer: AppUser) => {
        const sellerEmail = await fetchUserEmail(listing.sellerUid);
        const threadId = await findOrCreateChatThread(listing, buyer, sellerEmail);
        if (threadId) {
            await fetchMessages(threadId);
            setActiveThreadId(threadId);
            setView('chat');
        }
    };

    const handleViewThread = async (id: string) => {
        await fetchMessages(id);
        setActiveThreadId(id);
        setView('chat');
    };

    const handleBuyNow = (car: CarListing) => {
        if (!currentUser) { setView('auth'); return; }
        setItemToBuy(car);
        setShowPaymentModal(true);
    };

    const handlePaymentConfirm = () => {
        if (itemToBuy && currentUser) {
            purchaseListing(itemToBuy.id, currentUser.uid);
            setShowPaymentModal(false);
            setSelectedCar({ ...itemToBuy, status: 'sold', buyerUid: currentUser.uid, purchaseDate: new Date().toISOString() });
            setView('invoice');
            setItemToBuy(null);
        }
    };

    const handleViewInvoice = (car: CarListing) => {
        setSelectedCar(car);
        setView('invoice');
    }

    const renderView = () => {
        if (view === 'invoice' && selectedCar && currentUser) {
            return <InvoiceView car={selectedCar} buyer={currentUser} onBack={() => setView('sell')} />;
        }

        return (
            <>
                <Header currentView={view} setView={setView} user={currentUser} onLogout={handleLogout} />
                {view === 'home' && <HomeView setView={setView} recentListings={recentListings} allListings={listings} currentUserId={currentUser?.uid || null} onViewDetail={handleViewDetail} />}
                {view === 'user-dashboard' && currentUser && !currentUser.isAdmin && <UserDashboardView user={currentUser} setView={setView} onViewDetail={handleViewDetail} onLogout={handleLogout} />}
                {view === 'listings' && <ListingsView listings={listings} currentUserId={currentUser?.uid || null} onViewDetail={handleViewDetail} />}
                {view === 'sell' && <SellCarPage currentUser={currentUser} onBack={() => setView('home')} />}
                {view === 'auth' && <AuthView onLogin={() => setView('user-dashboard')} onSignUp={async (n, e, p, m) => { const res = await signUp(n, e, p, m); if (res.success) setView('user-dashboard'); return res; }} onLoginAttempt={async (e, p) => { const res = await logIn(e, p); if (res.success) setView('user-dashboard'); return res; }} setView={setView} />}
                {view === 'admin-auth' && <AdminAuthView onAdminLogin={async (e, p) => { const res = await adminLogIn(e, p); if (res.success) setView('admin'); return res; }} setView={setView} />}
                {view === 'detail' && selectedCar && <CarDetailView car={selectedCar} onBack={() => setView('listings')} currentUser={currentUser} onContactSeller={handleContactSeller} onBuyNow={handleBuyNow} />}
                {view === 'inbox' && currentUser && <InboxView threads={getThreads(currentUser.uid)} currentUser={currentUser} onViewThread={handleViewThread} />}
                {view === 'chat' && activeThreadId && currentUser && <ChatView thread={getThread(activeThreadId)} messages={getMessages(activeThreadId)} currentUser={currentUser} onSendMessage={(txt) => sendMessage(activeThreadId, txt, currentUser.uid)} onBack={() => setView('inbox')} />}
                {view === 'admin' && currentUser?.isAdmin && <AdminPage onBack={() => { handleLogout(); setView('home'); }} />}
            </>
        );
    };

    return (
        <div style={{ minHeight: '100vh', backgroundColor: '#111827', fontFamily: 'Inter, sans-serif', color: '#f3f4f6' }}>
            <style>
                {`
                    * { box-sizing: border-box; }
                    body { margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
                    button { cursor: pointer; border: none; transition: all 0.2s; border-radius: 8px; }
                    input, select, textarea { color: #f3f4f6; background-color: #374151; border: 1px solid #4f46e5; padding: 12px; border-radius: 8px; outline: none; }
                    input:focus, select:focus, textarea:focus { border-color: #6366f1; box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.5); }
                    .btn-primary { background-color: #4f46e5; color: white; font-weight: bold; padding: 12px 16px; }
                    .btn-primary:hover { background-color: #6366f1; }
                    .btn-secondary { background-color: #9333ea; color: white; font-weight: bold; padding: 12px 24px; }
                    .btn-tertiary { background-color: #10b981; color: white; font-weight: bold; padding: 8px 16px; }
                    .btn-cancel { background-color: #4b5563; color: white; font-weight: bold; padding: 12px 16px; }
                    .btn-action { display: flex; align-items: center; justify-content: center; flex: 1; font-size: 14px; font-weight: 500; padding: 8px 12px; border-radius: 8px; color: white; }
                    .btn-action.edit { background-color: #9333ea; }
                    .btn-action.delete { background-color: #dc2626; }
                    .home-search-grid, .listings-grid, .my-listings-grid { display: grid; gap: 16px; }
                    .inbox-item:hover { background-color: #374151; }

                    @media (min-width: 768px) {
                        .header-nav-desktop { display: flex; gap: 24px; }
                        .home-search-grid { grid-template-columns: repeat(4, 1fr); }
                        .home-listings-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 32px; }
                        .listings-grid, .my-listings-grid { grid-template-columns: repeat(2, 1fr); gap: 32px; }
                        .detail-grid-container { display: grid; grid-template-columns: 3fr 2fr; gap: 32px; }
                        .sell-grid-container { display: grid; grid-template-columns: 1fr 2fr; gap: 48px; }
                    }
                    @media (min-width: 1024px) {
                        .listings-grid { grid-template-columns: repeat(3, 1fr); }
                    }
                `}
            </style>
            {renderView()}

            {showPaymentModal && itemToBuy && (
                <PaymentModal car={itemToBuy} onClose={() => setShowPaymentModal(false)} onConfirmPayment={handlePaymentConfirm} />
            )}
        </div>
    );
};

export default App;
