-- Update existing users to have ROLE_ADMIN by default
-- This will run after the schema is updated with the role column
-- Only update if the role column exists and is NULL
UPDATE users SET role = 'ROLE_ADMIN' WHERE role IS NULL OR role = 'ROLE_USER';
