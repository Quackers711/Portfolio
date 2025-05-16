import { useState } from 'react';

export default function UnlockForm({ slug }) {
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    const password = e.target.password.value;
    const res = await fetch('/api/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ slug, password }),
    });

    if (res.ok) {
      window.location.reload();
    } else {
      setError('Incorrect password');
    }
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="mt-8 flex flex-col items-center gap-4 max-w-sm mx-auto p-6 rounded-2xl border border-gray-200 shadow-sm bg-white"
    >
      <label htmlFor="password" className="text-lg font-semibold text-gray-700">
        Password
      </label>
      <input
        type="password"
        name="password"
        id="password"
        required
        placeholder="Enter password"
        className="w-full px-4 py-2 rounded-full border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
      />
      <button
        type="submit"
        className="px-5 py-2 bg-blue-600 text-white text-sm font-semibold rounded-full hover:bg-blue-700 transition"
      >
        Unlock
      </button>
      {error && <p className="text-red-600 text-sm font-medium">{error}</p>}
    </form>
  );
}
