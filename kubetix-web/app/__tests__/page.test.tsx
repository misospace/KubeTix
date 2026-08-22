/** @vitest-environment jsdom */
import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import Home from "../page"

const axiosMock = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  delete: vi.fn(),
}))

vi.mock("axios", () => ({ default: axiosMock }))

const user = {
  id: "user-1",
  email: "operator@example.com",
  full_name: "Cluster Operator",
  is_admin: true,
  created_at: "2026-01-01T00:00:00Z",
}

const grant = {
  id: "grant-1",
  cluster_name: "production",
  namespace: "payments",
  role: "view",
  created_at: "2026-01-01T00:00:00Z",
  expires_at: "2099-01-01T00:00:00Z",
  revoked: false,
}

function authenticatedApi(grants = [grant]) {
  axiosMock.get.mockImplementation((url: string) => {
    if (url.includes("/users/me")) return Promise.resolve({ data: user })
    if (url.includes("/grants")) return Promise.resolve({ data: grants })
    return Promise.reject(new Error(`Unexpected GET ${url}`))
  })
}

function buttonMatching(pattern: RegExp): HTMLButtonElement {
  const button = screen.getAllByRole("button").find((candidate) => {
    const label = [
      candidate.textContent,
      candidate.getAttribute("aria-label"),
      candidate.getAttribute("title"),
    ].join(" ")
    return pattern.test(label)
  })
  if (!button) throw new Error(`Could not find button matching ${pattern}`)
  return button as HTMLButtonElement
}

beforeEach(() => {
  axiosMock.get.mockReset()
  axiosMock.post.mockReset()
  axiosMock.delete.mockReset()
  process.env.NEXT_PUBLIC_API_URL = "https://api.example.test"
})

afterEach(() => {
  delete process.env.NEXT_PUBLIC_API_URL
})

describe("Home page authentication", () => {
  it("renders the login screen for unauthenticated users", async () => {
    axiosMock.get.mockRejectedValue(new Error("Unauthenticated"))

    render(<Home />)

    expect(await screen.findByText("KubeTix")).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/you@example\.com/i)).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/password/i)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument()
    expect(axiosMock.get).toHaveBeenCalledWith(
      "https://api.example.test/api/v1/users/me",
      { withCredentials: true },
    )
  })

  it("logs in with cookie credentials and loads the grants", async () => {
    authenticatedApi()
    axiosMock.post.mockResolvedValue({ data: { access_token: "ignored", token_type: "bearer", user } })
    const userEventInstance = userEvent.setup()

    render(<Home />)
    await screen.findByPlaceholderText(/you@example\.com/i)
    await userEventInstance.type(screen.getByPlaceholderText(/you@example\.com/i), user.email)
    await userEventInstance.type(screen.getByPlaceholderText(/password/i), "correct-horse")
    await userEventInstance.click(screen.getByRole("button", { name: /sign in/i }))

    expect(axiosMock.post).toHaveBeenCalledWith(
      "https://api.example.test/api/v1/login",
      { email: user.email, password: "correct-horse" },
      { withCredentials: true },
    )
    expect(await screen.findByText("production")).toBeInTheDocument()
    expect(axiosMock.get).toHaveBeenCalledWith(
      "https://api.example.test/api/v1/grants",
      { withCredentials: true },
    )
  })

  it("starts SSO using the API redirect and logs out with credentials", async () => {
    axiosMock.get.mockRejectedValue(new Error("Unauthenticated"))
    axiosMock.post.mockResolvedValue({ data: { access_token: "ignored", token_type: "bearer", user } })
    const userEventInstance = userEvent.setup()
    const location = window.location
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...location, href: "", assign: vi.fn() },
    })

    render(<Home />)
    await screen.findByPlaceholderText(/you@example\.com/i)
    await userEventInstance.click(buttonMatching(/sso|single sign-on|oidc/i))
    expect(window.location.href).toContain("https://api.example.test")
    expect(window.location.href).toMatch(/sso|oidc/i)

    Object.defineProperty(window, "location", { configurable: true, value: location })
  })
})

describe("grant management", () => {
  it("lists active grants and requests them with cookie credentials", async () => {
    authenticatedApi()

    render(<Home />)

    expect(await screen.findByText("production")).toBeInTheDocument()
    expect(screen.getByText("payments")).toBeInTheDocument()
    expect(screen.getByText("view")).toBeInTheDocument()
    expect(axiosMock.get).toHaveBeenCalledWith(
      "https://api.example.test/api/v1/grants",
      { withCredentials: true },
    )
  })

  it("creates an admin grant and renders the returned grant", async () => {
    authenticatedApi([])
    const createdGrant = { ...grant, id: "grant-2", cluster_name: "staging", namespace: null, role: "admin" }
    axiosMock.post.mockResolvedValue({ data: createdGrant })
    const userEventInstance = userEvent.setup()

    render(<Home />)
    await screen.findByText(/no grants|create your first/i)
    await userEventInstance.click(buttonMatching(/create|new grant|issue/i))

    const dialog = screen.queryByRole("dialog") ?? document.body
    const clusterControl = within(dialog).getByLabelText(/cluster/i)
    if (clusterControl.tagName === "SELECT") {
      await userEventInstance.selectOptions(clusterControl, "staging")
    } else {
      await userEventInstance.clear(clusterControl)
      await userEventInstance.type(clusterControl, "staging")
    }
    const namespaceControl = within(dialog).queryByLabelText(/namespace/i)
    if (namespaceControl) await userEventInstance.clear(namespaceControl)
    const roleControl = within(dialog).queryByLabelText(/role/i)
    if (roleControl?.tagName === "SELECT") await userEventInstance.selectOptions(roleControl, "admin")
    await userEventInstance.click(buttonMatching(/create|issue|generate/i))

    expect(axiosMock.post).toHaveBeenCalledWith(
      "https://api.example.test/api/v1/grants",
      expect.objectContaining({ cluster_name: "staging", role: "admin" }),
      { withCredentials: true },
    )
    expect(await screen.findByText("staging")).toBeInTheDocument()
  })

  it("downloads a kubeconfig and revokes a grant", async () => {
    authenticatedApi()
    axiosMock.get.mockImplementation((url: string) => {
      if (url.includes("/users/me")) return Promise.resolve({ data: user })
      if (url.includes("/grants")) return Promise.resolve({ data: [grant] })
      return Promise.resolve({ data: "apiVersion: v1" })
    })
    axiosMock.delete.mockResolvedValue({})
    const userEventInstance = userEvent.setup()

    render(<Home />)
    await screen.findByText("production")
    await userEventInstance.click(buttonMatching(/download|kubeconfig/i))
    await waitFor(() => expect(axiosMock.get).toHaveBeenCalledWith(
      expect.stringMatching(/grants\/grant-1\/.*(download|kubeconfig)/),
      expect.objectContaining({ withCredentials: true }),
    ))

    await userEventInstance.click(buttonMatching(/revoke/i))
    const confirm = screen.queryByRole("button", { name: /confirm|revoke/i })
    if (confirm) await userEventInstance.click(confirm)
    expect(axiosMock.delete).toHaveBeenCalledWith(
      "https://api.example.test/api/v1/grants/grant-1",
      { withCredentials: true },
    )
  })
})
