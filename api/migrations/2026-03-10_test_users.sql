-- Test registrations (TEST1 TEST – TEST10 TEST)
-- Run with: wrangler d1 execute <DB_NAME> --file=migrations/2026-03-10_test_users.sql

INSERT INTO registrations (id, reg_number, created_at, name, email, phone, address, car_year, car_make, car_model, car_color, class, attended_before, tshirt_size, has_home_church, home_church_name, checked_in_at, notes)
VALUES
  ('test-00000000-0001',  1, '2026-03-10T12:00:00Z', 'TEST1 TEST',  'test1@example.com',  '555-000-0001', '123 Test St, Testville, TX 75001', '2001', 'Ford',       'F-150',    'Red',    'car_truck',  'no',  'medium', 'yes', 'Test Church', NULL, 'test user'),
  ('test-00000000-0002',  2, '2026-03-10T12:00:00Z', 'TEST2 TEST',  'test2@example.com',  '555-000-0002', '123 Test St, Testville, TX 75001', '2002', 'Chevrolet',  'Camaro',   'Blue',   'car_truck',  'yes', 'large',  'no',  NULL,          NULL, 'test user'),
  ('test-00000000-0003',  3, '2026-03-10T12:00:00Z', 'TEST3 TEST',  'test3@example.com',  '555-000-0003', '123 Test St, Testville, TX 75001', '2003', 'Dodge',      'Charger',  'Black',  'car_truck',  'no',  'xl',     'yes', 'Test Church', NULL, 'test user'),
  ('test-00000000-0004',  4, '2026-03-10T12:00:00Z', 'TEST4 TEST',  'test4@example.com',  '555-000-0004', '123 Test St, Testville, TX 75001', '2004', 'Honda',      'Civic',    'White',  'car_truck',  'yes', 'small',  'no',  NULL,          NULL, 'test user'),
  ('test-00000000-0005',  5, '2026-03-10T12:00:00Z', 'TEST5 TEST',  'test5@example.com',  '555-000-0005', '123 Test St, Testville, TX 75001', '2005', 'Toyota',     'Tacoma',   'Silver', 'car_truck',  'no',  '2xl',    'yes', 'Test Church', NULL, 'test user'),
  ('test-00000000-0006',  6, '2026-03-10T12:00:00Z', 'TEST6 TEST',  'test6@example.com',  '555-000-0006', '123 Test St, Testville, TX 75001', '2006', 'Harley-Davidson', 'Softail', 'Orange', 'motorcycle', 'no',  'medium', 'no',  NULL,     NULL, 'test user'),
  ('test-00000000-0007',  7, '2026-03-10T12:00:00Z', 'TEST7 TEST',  'test7@example.com',  '555-000-0007', '123 Test St, Testville, TX 75001', '2007', 'Kawasaki',   'Ninja',    'Green',  'motorcycle', 'yes', 'large',  'yes', 'Test Church', NULL, 'test user'),
  ('test-00000000-0008',  8, '2026-03-10T12:00:00Z', 'TEST8 TEST',  'test8@example.com',  '555-000-0008', '123 Test St, Testville, TX 75001', '2008', 'Jeep',       'Wrangler', 'Yellow', 'other',      'no',  'xl',     'no',  NULL,          NULL, 'test user'),
  ('test-00000000-0009',  9, '2026-03-10T12:00:00Z', 'TEST9 TEST',  'test9@example.com',  '555-000-0009', '123 Test St, Testville, TX 75001', '2009', 'Ford',       'Mustang',  'Purple', 'car_truck',  'yes', '3xl',    'yes', 'Test Church', NULL, 'test user'),
  ('test-00000000-0010', 10, '2026-03-10T12:00:00Z', 'TEST10 TEST', 'test10@example.com', '555-000-0010', '123 Test St, Testville, TX 75001', '2010', 'Chevrolet',  'Silverado','Gray',   'car_truck',  'no',  'medium', 'no',  NULL,          NULL, 'test user');
