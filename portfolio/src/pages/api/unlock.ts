import type { APIRoute } from 'astro';
import { loadEnv } from 'vite';

export const prerender = false

const env = loadEnv("", process.cwd());

export const POST: APIRoute = async ({ request }) => {
    try {
      const body = await request.json(); // this throws if no body or bad JSON
      const { slug, password } = body;
  
      const passwords = JSON.parse('{"ddc25-national-writeups": "password", "another-post": "letmein"}');
      const expected = passwords[slug];
  
      if (password && password === expected) {
        
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: {
            'Set-Cookie': `unlocked_${slug}=true; Path=/; HttpOnly; SameSite=Strict`,
          },
        });
      }
  
      return new Response(JSON.stringify({ success: false }), { status: 401 });
    } catch (err) {
      return new Response(JSON.stringify({ error: 'Invalid JSON' }), { status: 400 });
    }
  };
  
