/** @vitest-environment jsdom */
import { render, screen } from "@testing-library/react"
import Home from "../page"

// Mock axios so the component does not attempt real API calls during tests.
vi.mock("axios", () => ({
  default: {
    get: vi.fn(() => Promise.reject(new Error("Network error"))),
    post: vi.fn(() => Promise.reject(new Error("Network error"))),
    delete: vi.fn(() => Promise.reject(new Error("Network error"))),
  },
}))

describe("Home page", () => {
  it("renders the login screen for unauthenticated users", async () => {
    render(<Home />)

    // Wait for auth loading to finish (component shows login when /users/me fails)
    await screen.findByText("KubeTix")

    expect(screen.getByPlaceholderText(/you@example\.com/i)).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/password/i)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument()
  })
})
