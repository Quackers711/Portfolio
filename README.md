# Portfolio
This is the repository for my personal developer portfolio. It showcases selected projects, blog posts, and custom-built features using modern web technologies.

This project builds upon the Astro Starter Kit Blog with custom functionality, components and styling.

## Planned
- Make tags clickable and implement search functionality.
- Custom styling.
- Blogpost images.
- Possibility to sign up for newsletter (Email on post).
- Locked icon on blog "index" on locked posts.
- Table of contents.
- Dark mode toggle.

## Custom implementation:
- Ability to lock blogs behind password authentication.
- Blogpost tags/categories.
- Table of contents.

## How to run
This project relies on an ``.env`` file that has the following structure:
```
POST_PASSWORDS='{"blog-slug": "pass"}'
```

Then the project can be run using ``npm run dev``.