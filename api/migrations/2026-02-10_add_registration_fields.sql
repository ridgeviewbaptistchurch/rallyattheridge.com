-- Adds additional registration fields for event operations.
ALTER TABLE registrations ADD COLUMN address TEXT;
ALTER TABLE registrations ADD COLUMN attended_before TEXT CHECK (attended_before IN ('yes','no'));
ALTER TABLE registrations ADD COLUMN tshirt_size TEXT CHECK (tshirt_size IN ('small','medium','large','xl','2xl','3xl'));
ALTER TABLE registrations ADD COLUMN has_home_church TEXT CHECK (has_home_church IN ('yes','no'));
ALTER TABLE registrations ADD COLUMN home_church_name TEXT;
