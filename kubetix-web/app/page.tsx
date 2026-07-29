"use client"

import { useState, useEffect, useCallback } from "react"
import axios from "axios"
import { formatDistanceToNow } from "date-fns"
import { 
  Key, 
  Clock, 
  Shield, 
  Copy, 
  Check, 
  AlertCircle,
  Plus,
  X,
  LogIn,
  Loader2,
  LogOut,
  EyeOff,
  User
} from "lucide-react"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Grant {
  id: string
  cluster_name: string
  namespace: string | null
  role: string
  created_at: string
  expires_at: string
  revoked: boolean
}

interface UserResponse {
  id: string
  email: string
  full_name: string | null
  is_admin: boolean
  created_at: string
}

interface AuthToken {
  access_token: string
  token_type: string
  user: UserResponse
}

// ---------------------------------------------------------------------------
// API client helpers
//
// The JWT is delivered by the API as an httpOnly + Secure cookie (set by
// /login and the SSO/OIDC callbacks). That keeps it out of JavaScript-readable
// storage (audit #144) so an XSS payload cannot read or exfiltrate it. All
// authenticated requests send `credentials: "include"` so the browser
// attaches the cookie automatically; we never need to read or write the
// token from JS.
// ---------------------------------------------------------------------------

const getApiUrl = (): string => {
  if (typeof window !== "undefined") {
    return process.env.NEXT_PUBLIC_API_URL || ""
  }
  return ""
}

// Always include the httpOnly auth cookie on same-origin / credentialed
// cross-origin requests.
const CREDENTIALS = { withCredentials: true } as const

async function apiLogin(email: string, password: string): Promise<AuthToken> {
  const apiUrl = getApiUrl()
  const resp = await axios.post(`${apiUrl}/login`, { email, password }, CREDENTIALS)
  // The token is only kept in an httpOnly cookie. We deliberately do NOT
  // read it here; the cookie is sent automatically by the browser.
  return resp.data
}

async function apiLogout(): Promise<void> {
  const apiUrl = getApiUrl()
  if (apiUrl) {
    try {
      await axios.post(`${apiUrl}/auth/logout`, {}, CREDENTIALS)
    } catch {
      // Best-effort: proceed with local cleanup even if server call fails
    }
  }
}

async function fetchGrants(): Promise<Grant[]> {
  const apiUrl = getApiUrl()
  const resp = await axios.get(`${apiUrl}/grants`, CREDENTIALS)
  return resp.data
}

async function createGrant(payload: {
  cluster_name: string
  namespace?: string | null
  role: string
  expiry_hours: number
}): Promise<Grant> {
  const apiUrl = getApiUrl()
  const resp = await axios.post(`${apiUrl}/grants`, payload, CREDENTIALS)
  return resp.data
}

async function revokeGrant(grantId: string): Promise<void> {
  const apiUrl = getApiUrl()
  await axios.delete(`${apiUrl}/grants/${grantId}`, CREDENTIALS)
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function Home() {
  const [grants, setGrants] = useState<Grant[]>([])
  const [loading, setLoading] = useState(true)
  const [authLoading, setAuthLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  
  // Auth state
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const [currentUser, setCurrentUser] = useState<UserResponse | null>(null)
  const [showLoginModal, setShowLoginModal] = useState(false)
  const [loginEmail, setLoginEmail] = useState("")
  const [loginPassword, setLoginPassword] = useState("")
  const [loginError, setLoginError] = useState<string | null>(null)
  const [loginSubmitting, setLoginSubmitting] = useState(false)

  // Form state for create grant
  const [clusterName, setClusterName] = useState("prod")
  const [namespace, setNamespace] = useState("")
  const [role, setRole] = useState("view")
  const [expiry, setExpiry] = useState(4)

  // Revoke confirmation state
  const [revokeConfirmId, setRevokeConfirmId] = useState<string | null>(null)
  const [revokeSubmitting, setRevokeSubmitting] = useState(false)

  // Create grant loading state
  const [creating, setCreating] = useState(false)

  // -----------------------------------------------------------------------
  // Lifecycle: check auth on mount and fetch grants
  // -----------------------------------------------------------------------

  useEffect(() => {
    checkAuthAndFetch()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const checkAuthAndFetch = useCallback(async () => {
    setAuthLoading(true)
    setError(null)

    // Validate the session by hitting /users/me. The httpOnly cookie is
    // sent automatically; a 401 means the user is not signed in.
    try {
      const apiUrl = getApiUrl()
      const resp = await axios.get(`${apiUrl}/users/me`, CREDENTIALS)
      setCurrentUser(resp.data)
      setIsLoggedIn(true)

      // Fetch grants after confirming auth
      const grantsData = await fetchGrants()
      setGrants(grantsData)
    } catch {
      // Session invalid or absent
      setIsLoggedIn(false)
      setCurrentUser(null)
    } finally {
      setAuthLoading(false)
      setLoading(false)
    }
  }, [])

  // -----------------------------------------------------------------------
  // Auth handlers
  // -----------------------------------------------------------------------

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoginError(null)
    setLoginSubmitting(true)
    
    try {
      const auth = await apiLogin(loginEmail, loginPassword)
      setCurrentUser(auth.user)
      setIsLoggedIn(true)
      setShowLoginModal(false)
      setLoginEmail("")
      setLoginPassword("")
      
      // Fetch grants after login
      const grantsData = await fetchGrants()
      setGrants(grantsData)
    } catch (err: any) {
      if (err.response?.data?.detail) {
        setLoginError(err.response.data.detail)
      } else {
        setLoginError("Failed to connect to the API server.")
      }
    } finally {
      setLoginSubmitting(false)
    }
  }

  const handleLogout = async () => {
    await apiLogout()
    setIsLoggedIn(false)
    setCurrentUser(null)
    setGrants([])
  }

  // -----------------------------------------------------------------------
  // Grant handlers
  // -----------------------------------------------------------------------

  const handleCreateGrant = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setCreating(true)
    
    try {
      await createGrant({
        cluster_name: clusterName,
        namespace: namespace || null,
        role,
        expiry_hours: expiry,
      })
      
      setShowCreateModal(false)
      // Reset form
      setClusterName("prod")
      setNamespace("")
      setRole("view")
      setExpiry(4)
      
      // Refresh grants list
      const grantsData = await fetchGrants()
      setGrants(grantsData)
    } catch (err: any) {
      if (err.response?.data?.detail) {
        setError(err.response.data.detail)
      } else {
        setError("Failed to create grant.")
      }
    } finally {
      setCreating(false)
    }
  }

  const handleRevokeConfirm = async () => {
    if (!revokeConfirmId) return
    
    setRevokeSubmitting(true)
    setError(null)
    
    try {
      await revokeGrant(revokeConfirmId)
      setRevokeConfirmId(null)
      
      // Refresh grants list
      const grantsData = await fetchGrants()
      setGrants(grantsData)
    } catch (err: any) {
      if (err.response?.data?.detail) {
        setError(err.response.data.detail)
      } else {
        setError("Failed to revoke grant.")
      }
    } finally {
      setRevokeSubmitting(false)
    }
  }

  // -----------------------------------------------------------------------
  // UI helpers
  // -----------------------------------------------------------------------

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopiedId(text)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const getRoleColor = (role: string) => {
    switch (role) {
      case "admin": return "bg-red-100 text-red-800"
      case "edit": return "bg-yellow-100 text-yellow-800"
      default: return "bg-green-100 text-green-800"
    }
  }

  const getTimeRemaining = (expiresAt: string) => {
    const now = new Date()
    const expiry = new Date(expiresAt)
    const diff = expiry.getTime() - now.getTime()
    
    if (diff <= 0) return "Expired"
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m remaining`
    return `${Math.floor(diff / 3600000)}h remaining`
  }

  // -----------------------------------------------------------------------
  // Auth loading state
  // -----------------------------------------------------------------------

  if (authLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary-500 mx-auto mb-4" />
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    )
  }

  // -----------------------------------------------------------------------
  // Not logged in — show login screen
  // -----------------------------------------------------------------------

  if (!isLoggedIn) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="bg-white rounded-xl shadow-lg p-8 max-w-md w-full mx-4">
          <div className="text-center mb-8">
            <div className="bg-primary-500 p-3 rounded-xl inline-block mb-4">
              <Key className="h-8 w-8 text-white" />
            </div>
            <h1 className="text-2xl font-bold text-gray-900">KubeTix</h1>
            <p className="text-sm text-gray-500 mt-1">Temporary Kubernetes Access</p>
          </div>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Email
              </label>
              <input
                type="email"
                value={loginEmail}
                onChange={(e) => setLoginEmail(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                placeholder="you@example.com"
                required
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Password
              </label>
              <input
                type="password"
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                placeholder="Password"
                required
              />
            </div>

            {loginError && (
              <div className="flex items-center space-x-2 text-red-600 text-sm bg-red-50 p-3 rounded-lg">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span>{loginError}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loginSubmitting}
              className="w-full bg-primary-500 hover:bg-primary-600 disabled:bg-primary-300 text-white px-4 py-2 rounded-lg flex items-center justify-center space-x-2 transition-colors"
            >
              {loginSubmitting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Signing in...</span>
                </>
              ) : (
                <>
                  <LogIn className="h-4 w-4" />
                  <span>Sign In</span>
                </>
              )}
            </button>
          </form>

          <p className="text-xs text-gray-400 text-center mt-6">
            First-time setup? <a href="https://github.com/misospace/KubeTix/blob/main/README.md" target="_blank" rel="noopener noreferrer" className="underline hover:text-gray-600">See the docs</a>
          </p>
        </div>
      </div>
    )
  }

  // -----------------------------------------------------------------------
  // Logged in — main dashboard
  // -----------------------------------------------------------------------

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      {/* Header */}
      <header className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex justify-between items-center">
            <div className="flex items-center space-x-3">
              <div className="bg-primary-500 p-2 rounded-lg">
                <Key className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">KubeTix</h1>
                <p className="text-sm text-gray-500">Temporary Kubernetes Access</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2 text-sm text-gray-600">
                <User className="h-4 w-4" />
                <span>{currentUser?.full_name || currentUser?.email}</span>
              </div>
              
              <button
                onClick={() => setShowCreateModal(true)}
                className="bg-primary-500 hover:bg-primary-600 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors"
              >
                <Plus className="h-4 w-4" />
                <span>Create Grant</span>
              </button>
              
              <button
                onClick={handleLogout}
                className="text-gray-500 hover:text-gray-700 p-2 hover:bg-gray-100 rounded-lg transition-colors"
                title="Sign Out"
              >
                <LogOut className="h-4 w-4" />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="mb-6 flex items-center space-x-2 text-red-600 bg-red-50 p-4 rounded-lg">
            <AlertCircle className="h-5 w-5 flex-shrink-0" />
            <span>{error}</span>
            <button
              onClick={() => setError(null)}
              className="ml-auto text-red-400 hover:text-red-600"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-white rounded-lg shadow-sm p-6">
            <div className="flex items-center space-x-3">
              <div className="bg-blue-100 p-2 rounded-lg">
                <Key className="h-5 w-5 text-blue-600" />
              </div>
              <div>
                <p className="text-sm text-gray-500">Active Grants</p>
                <p className="text-2xl font-bold text-gray-900">{grants.length}</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-lg shadow-sm p-6">
            <div className="flex items-center space-x-3">
              <div className="bg-yellow-100 p-2 rounded-lg">
                <Clock className="h-5 w-5 text-yellow-600" />
              </div>
              <div>
                <p className="text-sm text-gray-500">Auto-Expiry</p>
                <p className="text-2xl font-bold text-gray-900">On</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-lg shadow-sm p-6">
            <div className="flex items-center space-x-3">
              <div className="bg-green-100 p-2 rounded-lg">
                <Shield className="h-5 w-5 text-green-600" />
              </div>
              <div>
                <p className="text-sm text-gray-500">Encryption</p>
                <p className="text-2xl font-bold text-gray-900">AES-128-CBC + HMAC</p>
              </div>
            </div>
          </div>
        </div>

        {/* Grants List */}
        <div className="bg-white rounded-lg shadow-sm">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">Active Grants</h2>
          </div>
          
          {loading ? (
            <div className="p-8 text-center">
              <Loader2 className="h-8 w-8 animate-spin border-b-2 border-primary-500 mx-auto mb-2" />
              <p className="text-gray-500">Loading grants...</p>
            </div>
          ) : grants.length === 0 ? (
            <div className="p-8 text-center">
              <AlertCircle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-500 mb-4">No active grants</p>
              <button
                onClick={() => setShowCreateModal(true)}
                className="bg-primary-500 hover:bg-primary-600 text-white px-4 py-2 rounded-lg"
              >
                Create Your First Grant
              </button>
            </div>
          ) : (
            <div className="divide-y divide-gray-200">
              {grants.map((grant) => (
                <div key={grant.id} className="p-6 hover:bg-gray-50 transition-colors">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <h3 className="text-lg font-semibold text-gray-900">{grant.cluster_name}</h3>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRoleColor(grant.role)}`}>
                          {grant.role}
                        </span>
                        {grant.namespace && (
                          <span className="px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                            {grant.namespace}
                          </span>
                        )}
                      </div>
                      
                      <div className="flex items-center space-x-4 text-sm text-gray-500 mb-3">
                        <div className="flex items-center space-x-1">
                          <Clock className="h-4 w-4" />
                          <span>{getTimeRemaining(grant.expires_at)}</span>
                        </div>
                        <div>
                          Created {formatDistanceToNow(new Date(grant.created_at), { addSuffix: true })}
                        </div>
                      </div>
                      
                      <div className="flex items-center space-x-2">
                        <code className="bg-gray-100 px-3 py-1 rounded text-sm text-gray-700">
                          {grant.id}
                        </code>
                        <button
                          onClick={() => copyToClipboard(grant.id)}
                          className="text-gray-400 hover:text-gray-600 transition-colors"
                          title="Copy ID"
                        >
                          {copiedId === grant.id ? (
                            <Check className="h-4 w-4 text-green-500" />
                          ) : (
                            <Copy className="h-4 w-4" />
                          )}
                        </button>
                      </div>
                    </div>
                    
                    {revokeConfirmId === grant.id ? (
                      <div className="flex items-center space-x-2">
                        <span className="text-sm text-red-600 font-medium">Revoke?</span>
                        <button
                          onClick={handleRevokeConfirm}
                          disabled={revokeSubmitting}
                          className="px-3 py-1 bg-red-600 hover:bg-red-700 disabled:bg-red-400 text-white text-sm rounded-lg transition-colors"
                        >
                          {revokeSubmitting ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            "Confirm"
                          )}
                        </button>
                        <button
                          onClick={() => setRevokeConfirmId(null)}
                          className="px-3 py-1 border border-gray-300 text-gray-600 hover:bg-gray-50 text-sm rounded-lg transition-colors"
                          disabled={revokeSubmitting}
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => setRevokeConfirmId(grant.id)}
                        className="text-red-600 hover:text-red-800 p-2 hover:bg-red-50 rounded-lg transition-colors"
                        title="Revoke Grant"
                      >
                        <EyeOff className="h-5 w-5" />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>

      {/* Create Grant Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl max-w-md w-full mx-4">
            <div className="px-6 py-4 border-b border-gray-200">
              <div className="flex justify-between items-center">
                <h3 className="text-lg font-semibold text-gray-900">Create Grant</h3>
                <button
                  onClick={() => setShowCreateModal(false)}
                  className="text-gray-400 hover:text-gray-600"
                  disabled={creating}
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
            </div>
            
            <form onSubmit={handleCreateGrant} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Cluster Name
                </label>
                <input
                  type="text"
                  value={clusterName}
                  onChange={(e) => setClusterName(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                  placeholder="prod"
                  required
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Namespace (optional)
                </label>
                <input
                  type="text"
                  value={namespace}
                  onChange={(e) => setNamespace(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                  placeholder="production"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Role
                </label>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                >
                  <option value="view">View</option>
                  <option value="edit">Edit</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Expiry (hours)
                </label>
                <select
                  value={expiry}
                  onChange={(e) => setExpiry(Number(e.target.value))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                >
                  <option value={1}>1 hour</option>
                  <option value={4}>4 hours</option>
                  <option value={8}>8 hours</option>
                  <option value={24}>24 hours</option>
                  <option value={168}>7 days</option>
                </select>
              </div>
              
              {error && (
                <div className="flex items-center space-x-2 text-red-600 text-sm bg-red-50 p-3 rounded-lg">
                  <AlertCircle className="h-4 w-4 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}
              
              <div className="flex space-x-3 pt-4">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="flex-1 px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors disabled:opacity-50"
                  disabled={creating}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors flex items-center justify-center space-x-2 disabled:opacity-50"
                  disabled={creating}
                >
                  {creating ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      <span>Creating...</span>
                    </>
                  ) : (
                    <span>Create Grant</span>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
