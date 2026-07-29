import "@testing-library/jest-dom/vitest";

// Ensure React treats the test environment as an act() environment so that
// createRoot flushes synchronously (required for React 19 + @testing-library/react).
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
