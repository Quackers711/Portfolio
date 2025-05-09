// src/components/UnlockForm.jsx
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
    <form onSubmit={handleSubmit}>
      <label>
        Password:
        <input type="password" name="password" required />
      </label>
      <button type="submit">Unlock</button>
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </form>
  );
}
