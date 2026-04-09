# Style Consistency Guide

This guide ensures that all pages have **consistent styling, colors, fonts, and spacing** throughout the application - especially for the Production user and all other roles.

## Design System Overview

### Color Palette (Defined in `global.css`)
- **Primary**: #3b82f6 (Blue)
- **Primary Light**: #eff6ff
- **Primary Dark**: #1e40af
- **Text Dark**: #0f172a (Main text)
- **Text Secondary**: #64748b (Secondary text)
- **Text Muted**: #94a3b8 (Muted text)
- **Background Soft**: #f8fafc
- **Background Light**: #f1f5f9
- **Border Light**: #e2e8f0
- **White**: #ffffff
- **Success**: #10b981
- **Warning**: #f59e0b
- **Error**: #ef4444

### Typography
- **Font Family**: Inter (fallback: system fonts)
- **Headings**: Bold, 700 weight
- **Body Text**: 14px, 400 weight
- **Line Height**: 1.6

## Component Style Classes

### Page Titles & Headers
```jsx
// Page Title
<h1 className="page-title">Page Name</h1>
<p className="page-subtitle">Page description here</p>

// Section Headers
<h2 className="section-header">Section Title</h2>
<h3 className="section-subheader">Sub Section Title</h3>
```

### Info Cards (Data Display)
```jsx
// Single Info Card
<div className="info-card">
  <div className="info-item">
    <label className="info-label">Label</label>
    <div className="info-value">Value</div>
  </div>
</div>

// Grid of Info Items
<div className="info-grid-3">
  <div className="info-card">
    <div className="info-item">
      <label className="info-label">Field 1</label>
      <div className="info-value">Data 1</div>
    </div>
  </div>
  <div className="info-card">
    <div className="info-item">
      <label className="info-label">Field 2</label>
      <div className="info-value">Data 2</div>
    </div>
  </div>
  <div className="info-card">
    <div className="info-item">
      <label className="info-label">Field 3</label>
      <div className="info-value">Data 3</div>
    </div>
  </div>
</div>
```

### Content Sections
```jsx
// Major content section with consistent padding and styling
<div className="content-section">
  <h2 className="section-header">Section Content</h2>
  {/* Content goes here */}
</div>
```

### Tab Navigation
```jsx
<div className="tab-list">
  <button className="tab-button active">Tab 1</button>
  <button className="tab-button">Tab 2</button>
  <button className="tab-button">Tab 3</button>
</div>
```

### Action Buttons
```jsx
// Left-aligned actions
<div className="action-bar">
  <button className="btn-primary">Add New</button>
  <button className="btn-secondary">Edit</button>
  <button className="btn-ghost">Delete</button>
</div>

// Right-aligned actions
<div className="action-bar-right">
  <button className="btn-primary">Save</button>
  <button className="btn-secondary">Cancel</button>
</div>
```

### Badges & Status Indicators
```jsx
<span className="badge">Default</span>
<span className="badge badge-primary">Primary</span>
<span className="badge badge-success">Success</span>
<span className="badge badge-warning">Warning</span>
<span className="badge badge-error">Error</span>
```

### Data Tables
```jsx
<table className="data-table">
  <thead>
    <tr>
      <th>Column 1</th>
      <th>Column 2</th>
      <th>Column 3</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Data 1</td>
      <td>Data 2</td>
      <td>Data 3</td>
    </tr>
  </tbody>
</table>
```

### Forms
```jsx
<div className="form-section">
  <div className="form-group">
    <label className="form-label required">Field Name</label>
    <input type="text" className="form-input" placeholder="Enter value" />
    <div className="form-help">Help text here</div>
  </div>

  <div className="form-group">
    <label className="form-label">Textarea Field</label>
    <textarea className="form-textarea" placeholder="Enter text"></textarea>
  </div>

  <div className="form-group">
    <label className="form-label">Select Field</label>
    <select className="form-select">
      <option>Option 1</option>
      <option>Option 2</option>
    </select>
  </div>
</div>
```

### Empty States
```jsx
<div className="empty-state">
  <div className="empty-state-icon">📦</div>
  <h3 className="empty-state-title">No Items Found</h3>
  <p className="empty-state-description">Start by adding a new item to get started</p>
</div>
```

### Messages & Alerts
```jsx
<div className="message-success">✓ Operation completed successfully</div>
<div className="message-error">✗ An error occurred</div>
<div className="message-warning">⚠ Warning message</div>
<div className="message-info">ℹ Information message</div>
```

## Grid Layouts

### 3-Column Grid
```jsx
<div className="info-grid-3">
  {/* 3 items will display in 1 col on mobile, 3 on desktop */}
</div>
```

### 4-Column Grid
```jsx
<div className="info-grid-4">
  {/* 4 items will display in 1 col on mobile, 2 on tablet, 4 on desktop */}
</div>
```

### Auto Grid
```jsx
<div className="info-grid">
  {/* Items will auto-flow based on container width */}
</div>
```

## Best Practices

1. **Always use semantic color variables** - Use `var(--primary)` instead of hardcoding colors
2. **Consistent spacing** - Use standard gap/margin values (4px increments)
3. **Typography hierarchy** - Use defined heading levels (h1, h2, h3, etc.)
4. **Border radius** - Use consistent border-radius values from the design system
5. **Shadows** - Use predefined shadow classes instead of custom ones
6. **Responsive design** - Use Tailwind's responsive prefixes (md:, lg:, etc.)
7. **Focus states** - All interactive elements must have visible focus indicators

## Production User Considerations

The Production user (role_id = 7) should see:
- Same consistent styling as all other users
- Same color scheme (Blue primary)
- Same fonts (Inter)
- Same spacing and layout patterns
- Same components across all pages
- No special styling that differs from other roles

## How to Apply These Styles

### Example: Recipe Detail Page
```jsx
export default function RecipeDetail() {
  return (
    <Layout>
      <div className="container-responsive">
        {/* Page Header */}
        <div className="mb-8">
          <h1 className="page-title">PISTA ROLL GREEN</h1>
          <p className="page-subtitle">View and manage recipe details</p>
        </div>

        {/* Info Cards */}
        <div className="content-section">
          <h2 className="section-header">Recipe Information</h2>
          <div className="info-grid-4">
            <div className="info-card">
              <div className="info-item">
                <label className="info-label">Recipe Code</label>
                <div className="info-value">RES027</div>
              </div>
            </div>
            {/* More cards */}
          </div>
        </div>

        {/* Tabs */}
        <div className="tab-list">
          <button className="tab-button active">Information</button>
          <button className="tab-button">History</button>
        </div>

        {/* Action Buttons */}
        <div className="action-bar">
          <button className="btn-primary">Edit</button>
          <button className="btn-secondary">Delete</button>
        </div>

        {/* Data Table */}
        <div className="content-section">
          <h2 className="section-header">Recipe Items</h2>
          <table className="data-table">
            {/* table content */}
          </table>
        </div>
      </div>
    </Layout>
  );
}
```

## Consistency Checklist

Use this checklist when working on any page:

- [ ] Page uses `page-title` and `page-subtitle` classes
- [ ] All section titles use `section-header` class
- [ ] Info items use `info-card` and `info-item` classes
- [ ] Forms use `form-section`, `form-group`, `form-label`, `form-input` classes
- [ ] Data tables use `data-table` class
- [ ] Buttons follow button style conventions (btn-primary, btn-secondary, btn-ghost)
- [ ] Colors come from CSS variables (not hardcoded)
- [ ] Spacing follows 4px grid system
- [ ] Fonts use Inter family
- [ ] All interactive elements have hover states
- [ ] Page is responsive (mobile, tablet, desktop)
- [ ] Accessibility standards are met (WCAG AA)

## Development

All these styles are defined in `client/global.css` in the `@layer components` section. To add new component styles:

1. Add the style class to `client/global.css`
2. Use semantic naming (e.g., `component-name`)
3. Use CSS variables for colors
4. Add hover/active states
5. Ensure responsive design
6. Document in this guide

---

**Last Updated**: 2026
**Version**: 1.0
