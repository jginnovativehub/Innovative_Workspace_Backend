const db = require('./db');
const { hashPassword } = require('./auth');

function seedDatabase(force = false) {
  if (!force && db.users.count() > 0) {
    console.log('Database already has records. Skipping seed.');
    return;
  }

  console.log('Clearing and seeding JG Innovative Hub database...');
  for (const collName of Object.keys(db)) {
    if (db[collName] && typeof db[collName].clear === 'function') {
      db[collName].clear();
    }
  }

  // 1. System Config
  db.systemConfigs.insertOne({
    id: 1,
    reportingWeekStart: 'Monday',
    reportingDeadlineDay: 'Friday',
    reportingDeadlineTime: '17:00',
    companyTimezone: 'Asia/Kolkata',
    maxFileSizeMb: 25,
    retentionDays: 365
  });

  // 2. Badges
  const badgesData = [
    {
      id: 1,
      code: 'sprint_champion',
      title: 'Sprint Champion',
      description: 'Submitted a milestone deliverable ahead of deadline with full acceptance test evidence.',
      icon: 'Zap',
      xpBonus: 150
    },
    {
      id: 2,
      code: 'flawless_report',
      title: 'Flawless Report',
      description: 'Weekly report accepted on first review with zero changes requested.',
      icon: 'Award',
      xpBonus: 100
    },
    {
      id: 3,
      code: 'blocker_buster',
      title: 'Blocker Buster',
      description: 'Reported and resolved a critical risk blocker with an approved recovery roadmap.',
      icon: 'ShieldCheck',
      xpBonus: 120
    },
    {
      id: 4,
      code: 'zero_overdue',
      title: 'Zero Overdue Streak',
      description: 'Achieved 4 consecutive weeks with 100% on-time milestone & task delivery.',
      icon: 'Target',
      xpBonus: 200
    },
    {
      id: 5,
      code: 'iron_reviewer',
      title: 'Iron Reviewer',
      description: 'Turned around pending deliverable reviews in under 24 hours.',
      icon: 'CheckCheck',
      xpBonus: 100
    },
    {
      id: 6,
      code: 'lead_pioneer',
      title: 'Pioneer Architect',
      description: 'Formulated and led company technical architecture specifications.',
      icon: 'Crown',
      xpBonus: 250
    }
  ];
  badgesData.forEach(b => db.badges.insertOne(b));

  // 3. Users (Admin, CEO, COO, Employees)
  const defaultPassword = hashPassword('Password123!');
  const admin = db.users.insertOne({
    id: 1,
    fullName: 'Platform Admin',
    email: 'admin@jginnovative.com',
    passwordHash: hashPassword('Admin123!'),
    role: 'ADMIN',
    department: 'Operations & IT',
    active: true,
    xp: 1500,
    level: 4,
    streakCount: 5,
    avatarTitle: 'Lead Architect',
    createdAt: '2026-07-15T09:00:00Z'
  });

  const ceo = db.users.insertOne({
    id: 2,
    fullName: 'Dr. Vikram Seth',
    email: 'ceo@jginnovative.com',
    passwordHash: hashPassword('Ceo123!'),
    role: 'CEO',
    department: 'Executive Management',
    active: true,
    xp: 2850,
    level: 5,
    streakCount: 8,
    avatarTitle: 'Master Pioneer',
    createdAt: '2026-07-15T09:00:00Z'
  });

  const coo = db.users.insertOne({
    id: 3,
    fullName: 'Anita Roy',
    email: 'coo@jginnovative.com',
    passwordHash: hashPassword('Coo123!'),
    role: 'COO',
    department: 'Operations Leadership',
    active: true,
    xp: 2420,
    level: 4,
    streakCount: 7,
    avatarTitle: 'Lead Architect',
    createdAt: '2026-07-15T09:00:00Z'
  });

  const alex = db.users.insertOne({
    id: 4,
    fullName: 'Alex Chen',
    email: 'alex.chen@jginnovative.com',
    passwordHash: hashPassword('Alex123!'),
    role: 'EMPLOYEE',
    department: 'Hardware & Electrical',
    active: true,
    xp: 980,
    level: 3,
    streakCount: 4,
    avatarTitle: 'System Craftsman',
    createdAt: '2026-08-01T09:00:00Z'
  });

  const kishor = db.users.insertOne({
    id: 5,
    fullName: 'kishor',
    email: 'kishor@inovative-hub.com',
    passwordHash: hashPassword('123456'),
    role: 'EMPLOYEE',
    department: 'Engineering',
    active: true,
    xp: 840,
    level: 3,
    streakCount: 3,
    avatarTitle: 'System Craftsman',
    createdAt: '2026-08-01T09:00:00Z'
  });

  const suvam = db.users.insertOne({
    id: 6,
    fullName: 'suvam',
    email: 'suvam@inovative-hub.com',
    passwordHash: hashPassword('123456'),
    role: 'EMPLOYEE',
    department: 'Engineering',
    active: true,
    xp: 420,
    level: 2,
    streakCount: 2,
    avatarTitle: 'Agile Builder',
    createdAt: '2026-09-01T09:00:00Z'
  });

  // User badges
  db.userBadges.insertOne({ userId: ceo.id, badgeId: 6, reason: 'Formulated strategic company baseline', awardedAt: '2026-08-10T10:00:00Z' });
  db.userBadges.insertOne({ userId: coo.id, badgeId: 5, reason: 'Rapid review response time < 24 hrs', awardedAt: '2026-09-01T10:00:00Z' });
  db.userBadges.insertOne({ userId: alex.id, badgeId: 1, reason: 'Finished Milestone 1 ahead of target', awardedAt: '2026-09-12T10:00:00Z' });
  db.userBadges.insertOne({ userId: alex.id, badgeId: 3, reason: 'Identified and mitigated MOSFET supply shortage', awardedAt: '2026-10-05T10:00:00Z' });
  db.userBadges.insertOne({ userId: kishor.id, badgeId: 2, reason: 'Flawless Week 38 progress report', awardedAt: '2026-09-28T10:00:00Z' });

  // 4. Project 1: Portable Power Station (SRS Appendix A - 8 Milestones)
  const proj1 = db.projects.insertOne({
    id: 1,
    code: 'PRJ-PPS-01',
    name: 'Portable Power Station — prototype and validation',
    objective: 'Design, assemble and validate a ruggedized 1.2kWh LiFePO4 battery power station with 1500W pure sine inverter and smart app telemetry.',
    scope: 'Covers electrical BMS design, dual-channel inverter PCB, firmware with thermal throttling, physical CNC enclosure, and safety compliance.',
    deliverables: 'Functional prototype unit, schematics, firmware source, safety certification lab test logs.',
    ownerId: ceo.id,
    status: 'ACTIVE',
    priority: 'CRITICAL',
    startDate: '2026-08-01',
    targetDate: '2026-11-30',
    createdAt: '2026-08-01T09:00:00Z'
  });

  // Memberships
  db.projectMemberships.insertOne({ projectId: proj1.id, userId: ceo.id, projectRole: 'PROJECT_OWNER' });
  db.projectMemberships.insertOne({ projectId: proj1.id, userId: coo.id, projectRole: 'LEAD_REVIEWER' });
  db.projectMemberships.insertOne({ projectId: proj1.id, userId: alex.id, projectRole: 'HARDWARE_LEAD' });
  db.projectMemberships.insertOne({ projectId: proj1.id, userId: kishor.id, projectRole: 'FIRMWARE_LEAD' });
  db.projectMemberships.insertOne({ projectId: proj1.id, userId: suvam.id, projectRole: 'QA_ENGINEER' });

  // 8 Milestones (Appendix A)
  const m1 = db.milestones.insertOne({
    id: 1,
    projectId: proj1.id,
    title: 'Requirements and system architecture',
    description: 'Comprehensive power budget, functional specs, safety interlocks and battery chemistry selection.',
    sequence: 1,
    ownerId: alex.id,
    reviewerId: coo.id,
    status: 'APPROVED_COMPLETED',
    startDate: '2026-08-01',
    dueDate: '2026-08-20',
    acceptanceCriteria: 'System architecture signed off by CEO & COO; thermal simulation margins > 25%; component BOM approved.',
    acceptedAt: '2026-08-19T14:30:00Z',
    evidenceNotes: 'Full architecture doc v1.2 attached and validated in simulation rig.',
    evidenceUrl: 'https://docs.jginnovative.internal/pps/arch-v1.2.pdf',
    xpReward: 300
  });

  const m2 = db.milestones.insertOne({
    id: 2,
    projectId: proj1.id,
    title: 'Electrical design and component selection',
    description: 'Schematic capture, active PFC circuit design, BMS balancing circuits, component sourcing.',
    sequence: 2,
    ownerId: alex.id,
    reviewerId: coo.id,
    status: 'APPROVED_COMPLETED',
    startDate: '2026-08-21',
    dueDate: '2026-09-15',
    acceptanceCriteria: 'Complete Altium schematics, BOM with dual-sourced critical silicon, thermal analysis for 1500W load.',
    acceptedAt: '2026-09-14T16:00:00Z',
    evidenceNotes: 'Hardware schematics and Gerber packages reviewed and sent for prototype fabrication.',
    evidenceUrl: 'https://docs.jginnovative.internal/pps/gerbers-revA.zip',
    xpReward: 300
  });

  const m3 = db.milestones.insertOne({
    id: 3,
    projectId: proj1.id,
    title: 'Firmware and user interface',
    description: 'Embedded C firmware for STM32 microcontrollers, CAN bus communications, and OLED/BLE telemetry interface.',
    sequence: 3,
    ownerId: kishor.id,
    reviewerId: coo.id,
    status: 'SUBMITTED_FOR_REVIEW',
    startDate: '2026-09-16',
    dueDate: '2026-10-15',
    acceptanceCriteria: 'State-of-Charge (SoC) Coulomb counter algorithm within 3% tolerance; fault trigger response < 10ms; BLE telemetry active.',
    evidenceNotes: 'Firmware commit tagged v0.9.4. Unit tests pass with 94% code coverage; logic analyzer traces attached.',
    evidenceUrl: 'https://github.com/jginnovative/pps-firmware/releases/tag/v0.9.4',
    xpReward: 350
  });

  const m4 = db.milestones.insertOne({
    id: 4,
    projectId: proj1.id,
    title: 'PCB/enclosure integration',
    description: 'Fabrication of Rev B PCB boards, CNC aluminum housing assembly, thermal heatsink fitting.',
    sequence: 4,
    ownerId: alex.id,
    reviewerId: coo.id,
    status: 'IN_PROGRESS',
    startDate: '2026-09-25',
    dueDate: '2026-10-22',
    acceptanceCriteria: 'Zero mechanical interference between heatsink and high-voltage busbars; IP54 sealing test passed.',
    xpReward: 300
  });

  const m5 = db.milestones.insertOne({
    id: 5,
    projectId: proj1.id,
    title: 'Prototype assembly',
    description: 'Physical integration of 4S4P battery pack, BMS module, inverter sub-chassis, and harness wiring.',
    sequence: 5,
    ownerId: alex.id,
    reviewerId: coo.id,
    status: 'NOT_STARTED',
    startDate: '2026-10-23',
    dueDate: '2026-11-05',
    acceptanceCriteria: '2 fully functional prototype units assembled; insulation resistance > 100M Ohm.',
    xpReward: 350
  });

  const m6 = db.milestones.insertOne({
    id: 6,
    projectId: proj1.id,
    title: 'Functional and safety testing',
    description: '1500W continuous load bench test, short-circuit protection verification, drop test, and thermal chamber cycling.',
    sequence: 6,
    ownerId: suvam.id,
    reviewerId: ceo.id,
    status: 'NOT_STARTED',
    startDate: '2026-11-06',
    dueDate: '2026-11-18',
    acceptanceCriteria: 'UL 2743 / IEC 62133 compliance checklist validated; zero runaway at 45°C ambient.',
    xpReward: 400
  });

  const m7 = db.milestones.insertOne({
    id: 7,
    projectId: proj1.id,
    title: 'Defect correction and regression testing',
    description: 'Triage bug tracker items identified in functional tests; patch firmware and hardware revisions.',
    sequence: 7,
    ownerId: kishor.id,
    reviewerId: coo.id,
    status: 'NOT_STARTED',
    startDate: '2026-11-19',
    dueDate: '2026-11-25',
    acceptanceCriteria: 'All Sev 1 and Sev 2 defects closed; regression test suite 100% green.',
    xpReward: 300
  });

  const m8 = db.milestones.insertOne({
    id: 8,
    projectId: proj1.id,
    title: 'Documentation and handover',
    description: 'Production assembly guide, calibration manuals, regulatory compliance filing, and manufacturing handoff.',
    sequence: 8,
    ownerId: alex.id,
    reviewerId: ceo.id,
    status: 'NOT_STARTED',
    startDate: '2026-11-26',
    dueDate: '2026-11-30',
    acceptanceCriteria: 'Manufacturing release package approved by CEO; bill of materials finalized.',
    xpReward: 300
  });

  // Milestone dependencies
  db.milestoneDependencies.insertOne({ milestoneId: m2.id, dependsOnMilestoneId: m1.id });
  db.milestoneDependencies.insertOne({ milestoneId: m3.id, dependsOnMilestoneId: m2.id });
  db.milestoneDependencies.insertOne({ milestoneId: m4.id, dependsOnMilestoneId: m2.id });
  db.milestoneDependencies.insertOne({ milestoneId: m5.id, dependsOnMilestoneId: m4.id });
  db.milestoneDependencies.insertOne({ milestoneId: m6.id, dependsOnMilestoneId: m5.id });
  db.milestoneDependencies.insertOne({ milestoneId: m7.id, dependsOnMilestoneId: m6.id });
  db.milestoneDependencies.insertOne({ milestoneId: m8.id, dependsOnMilestoneId: m7.id });

  // Tasks under milestones
  const t1 = db.tasks.insertOne({
    id: 1,
    projectId: proj1.id,
    milestoneId: m3.id,
    title: 'Implement Coulomb counter SoC estimation',
    description: 'Write discrete Kalman filter for battery State-of-Charge estimation using high-precision ADC current shunt.',
    ownerId: kishor.id,
    status: 'APPROVED_COMPLETED',
    priority: 'HIGH',
    startDate: '2026-09-18',
    dueDate: '2026-10-02',
    originalDueDate: '2026-10-02',
    acceptanceCriteria: 'Accurate to within 2.5% under dynamic pulsed load discharge.',
    deliverableExpected: 'Git pull request #42 and MATLAB verification report.',
    completedAt: '2026-10-01T15:00:00Z',
    xpReward: 80
  });

  const t2 = db.tasks.insertOne({
    id: 2,
    projectId: proj1.id,
    milestoneId: m3.id,
    title: 'OLED UI menu and BLE advertising stack',
    description: 'Implement display drivers for 1.3-inch OLED and Nordic nRF52 BLE telemetry broadcast service.',
    ownerId: kishor.id,
    status: 'SUBMITTED_FOR_REVIEW',
    priority: 'MEDIUM',
    startDate: '2026-10-03',
    dueDate: '2026-10-14',
    originalDueDate: '2026-10-14',
    acceptanceCriteria: 'Smooth 30 FPS menu animations; packet rate 5Hz over BLE.',
    deliverableExpected: 'Firmware binary v0.9.4 and video demonstration.',
    submittedAt: '2026-10-10T16:00:00Z',
    xpReward: 80
  });

  // Task with active Blocker (SRS 10.2 example)
  const t3 = db.tasks.insertOne({
    id: 3,
    projectId: proj1.id,
    milestoneId: m4.id,
    title: 'Power Board Rev B routing and thermal relief',
    description: 'Route 4oz copper heavy power traces for 100A peak current discharge.',
    ownerId: alex.id,
    status: 'BLOCKED',
    priority: 'CRITICAL',
    startDate: '2026-09-28',
    dueDate: '2026-10-14',
    originalDueDate: '2026-10-14',
    acceptanceCriteria: 'Thermal vias calculation verified; zero trace bottlenecks > 45°C rise.',
    deliverableExpected: 'Altium PCB layout and Gerber file package.',
    xpReward: 100
  });

  const t4 = db.tasks.insertOne({
    id: 4,
    projectId: proj1.id,
    milestoneId: m4.id,
    title: 'CNC aluminum case tolerance fit check',
    description: 'Coordinate with machine shop on anodized chassis dimensions and silicone gasket channels.',
    ownerId: alex.id,
    status: 'IN_PROGRESS',
    priority: 'MEDIUM',
    startDate: '2026-10-05',
    dueDate: '2026-10-20',
    originalDueDate: '2026-10-20',
    acceptanceCriteria: 'Case test fit holds Rev B board with ±0.2mm precision.',
    deliverableExpected: 'Inspection report and CMM measurement sheet.',
    xpReward: 80
  });

  db.taskDependencies.insertOne({ taskId: t2.id, dependsOnTaskId: t1.id });

  // Progress Update & Blocker Report on Task 3 (SRS 10.2)
  db.progressUpdates.insertOne({
    id: 1,
    taskId: t3.id,
    milestoneId: m4.id,
    authorId: alex.id,
    statusSnapshot: 'BLOCKED',
    note: 'Protection module MOSFET supply line discontinued by distributor; testing alternative Vishay package.',
    workLog: 'Completed 80% routing. Halted at output stage awaiting alternative footprint verification.',
    isBlocker: true,
    blockerReason: 'Distributor out of stock for primary N-channel MOSFET; pin-compatible replacement has wider pitch.',
    impact: 'Assembly cannot proceed to board spinning; potential 4-day setback if redesign needed.',
    proposedSolution: 'Re-route pad geometry to accept universal dual-footprint D2PAK/TOLL package.',
    expectedResolutionDate: '2026-10-18',
    supportNeeded: 'Approval to procure sample batch of Vishay SQJQ144ER from Mouser expedited.',
    createdAt: '2026-10-10T14:00:00Z'
  });

  // Schedule Change Request for Task 3 (SRS 6.4)
  db.scheduleRequests.insertOne({
    id: 1,
    taskId: t3.id,
    milestoneId: m4.id,
    requesterId: alex.id,
    oldDueDate: '2026-10-14',
    newDueDate: '2026-10-18',
    reason: 'Vendor footprint modification requires extra thermal copper re-simulation and pad verification.',
    status: 'PENDING',
    createdAt: '2026-10-10T15:30:00Z'
  });

  // 5. Project 2: AI Edge Vision (Demonstrating 3 Milestones)
  const proj2 = db.projects.insertOne({
    id: 2,
    code: 'PRJ-AI-02',
    name: 'AI Edge Vision Defect Detector',
    objective: 'Deploy automated visual quality inspection using edge YOLO neural model on high-speed conveyor line.',
    scope: 'Camera enclosure, Jetson Orin Nano integration, neural training, PLC alert relay.',
    deliverables: 'Edge inference box, trained defect model, production station.',
    ownerId: coo.id,
    status: 'ACTIVE',
    priority: 'HIGH',
    startDate: '2026-09-15',
    targetDate: '2026-11-15',
    createdAt: '2026-09-15T09:00:00Z'
  });
  db.projectMemberships.insertOne({ projectId: proj2.id, userId: coo.id, projectRole: 'PROJECT_OWNER' });
  db.projectMemberships.insertOne({ projectId: proj2.id, userId: suvam.id, projectRole: 'LEAD_TESTER' });

  db.milestones.insertOne({
    id: 9,
    projectId: proj2.id,
    title: 'Hardware rig & camera calibration',
    description: 'Rig mount setup, telecentric lens selection, strobe lighting sync.',
    sequence: 1,
    ownerId: suvam.id,
    reviewerId: coo.id,
    status: 'APPROVED_COMPLETED',
    startDate: '2026-09-15',
    dueDate: '2026-09-30',
    acceptanceCriteria: 'Sub-millimeter resolution achieved at 1.5m conveyor speed; 0% blur.',
    acceptedAt: '2026-09-29T11:00:00Z',
    evidenceNotes: 'Calibration grid test charts verified.',
    xpReward: 250
  });

  db.milestones.insertOne({
    id: 10,
    projectId: proj2.id,
    title: 'Model training & edge inference pipeline',
    description: 'Dataset collection of 5,000 scratch/dent samples; TensorRT INT8 optimization.',
    sequence: 2,
    ownerId: suvam.id,
    reviewerId: coo.id,
    status: 'IN_PROGRESS',
    startDate: '2026-10-01',
    dueDate: '2026-10-25',
    acceptanceCriteria: 'Precision >= 98.5%, inference latency < 25ms on Orin Nano.',
    xpReward: 350
  });

  db.milestones.insertOne({
    id: 11,
    projectId: proj2.id,
    title: 'Factory line integration & acceptance testing',
    description: 'Direct PLC digital output trigger, rejection piston air-solenoid integration.',
    sequence: 3,
    ownerId: suvam.id,
    reviewerId: coo.id,
    status: 'NOT_STARTED',
    startDate: '2026-10-26',
    dueDate: '2026-11-15',
    acceptanceCriteria: 'Continuous 48-hour burn-in trial with zero false rejection jams.',
    xpReward: 300
  });

  // 6. Project 3: Smart Industrial IoT Gateway 4.0 (Demonstrating 12 Milestones configurable)
  const proj3 = db.projects.insertOne({
    id: 3,
    code: 'PRJ-IOT-03',
    name: 'Smart Industrial IoT Gateway 4.0',
    objective: 'Next-gen telemetry gateway with dual isolated RS485, Modbus-RTU, dual SIM 4G LTE, and Edge MQTT broker.',
    scope: 'Full 12-stage hardware, software, security certification and field trial.',
    deliverables: 'Certified industrial gateway hardware with secure boot.',
    ownerId: ceo.id,
    status: 'ACTIVE',
    priority: 'MEDIUM',
    startDate: '2026-09-01',
    targetDate: '2027-01-30',
    createdAt: '2026-09-01T09:00:00Z'
  });
  db.projectMemberships.insertOne({ projectId: proj3.id, userId: ceo.id, projectRole: 'PROJECT_OWNER' });
  db.projectMemberships.insertOne({ projectId: proj3.id, userId: alex.id, projectRole: 'HARDWARE_LEAD' });
  db.projectMemberships.insertOne({ projectId: proj3.id, userId: kishor.id, projectRole: 'FIRMWARE_LEAD' });

  for (let i = 1; i <= 12; i++) {
    const statusVal = i === 1 ? 'APPROVED_COMPLETED' : (i === 2 ? 'IN_PROGRESS' : 'NOT_STARTED');
    db.milestones.insertOne({
      id: 11 + i,
      projectId: proj3.id,
      title: `Stage ${i}: System Sub-Module Phase ${i}`,
      description: `Industrial automation milestone stage #${i} testing module reliability.`,
      sequence: i,
      ownerId: i % 2 === 1 ? alex.id : kishor.id,
      reviewerId: ceo.id,
      status: statusVal,
      startDate: '2026-10-01',
      dueDate: `2026-1${i > 9 ? '2' : '1'}-${String((i * 2) % 28 + 1).padStart(2, '0')}`,
      acceptanceCriteria: `Sign-off verification checklist #${i} signed by engineering lead.`,
      xpReward: 200
    });
  }

  // 7. Weekly Reports & Versions (SRS 6.1 - 6.2)
  // Report 1: Alex Chen (SUBMITTED)
  const repAlex = db.weeklyReports.insertOne({
    id: 1,
    userId: alex.id,
    periodStart: '2026-10-05',
    periodEnd: '2026-10-09',
    status: 'SUBMITTED',
    currentVersion: 1,
    submittedAt: '2026-10-09T16:30:00Z',
    reviewedBy: coo.id,
    xpAwarded: 50
  });

  db.weeklyReportVersions.insertOne({
    id: 1,
    reportId: repAlex.id,
    versionNumber: 1,
    completedThisWeek: 'Finalized thermal dissipation calculations for Power Station 1500W stage; assembled Rev B chassis frame.',
    inProgress: 'Routing heavy copper busbar on Power Board; collaborating with machine shop on tolerance checks.',
    blockersRisks: 'Discontinuation of primary MOSFET by vendor. Impact is manageable via dual-footprint pad layout.',
    reasonForDelay: 'Distributor stock-out required alternative component qualification.',
    proposedSolution: 'Procure Vishay SQJQ144ER samples and re-route pad layout to dual-compatibility.',
    nextWeekPlan: 'Complete board layout, submit gerbers to fab house, test thermal fit with mock CNC block.',
    supportDecisionsRequired: 'Approval for expedited sample purchase order PO-8849 ($42).',
    submittedAt: '2026-10-09T16:30:00Z',
    submittedBy: alex.id
  });

  // Report 2: Priya Patel (CHANGES_REQUESTED with 2 versions!)
  const repPriya = db.weeklyReports.insertOne({
    id: 2,
    userId: kishor.id,
    periodStart: '2026-10-05',
    periodEnd: '2026-10-09',
    status: 'CHANGES_REQUESTED',
    currentVersion: 2,
    submittedAt: '2026-10-10T10:00:00Z',
    reviewedBy: coo.id,
    reviewedAt: '2026-10-10T14:00:00Z',
    reviewerFeedback: 'Please provide the exact logic analyzer traces for the 10ms fault cut-off test and quantify the SoC error margin under pulsed discharge.',
    xpAwarded: 0
  });

  db.weeklyReportVersions.insertOne({
    id: 2,
    reportId: repPriya.id,
    versionNumber: 1,
    completedThisWeek: 'Wrote SoC coulomb counting code.',
    inProgress: 'Testing display drivers.',
    blockersRisks: 'None',
    nextWeekPlan: 'Finish UI.',
    submittedAt: '2026-10-09T17:00:00Z',
    submittedBy: kishor.id
  });

  db.weeklyReportVersions.insertOne({
    id: 3,
    reportId: repPriya.id,
    versionNumber: 2,
    completedThisWeek: 'Integrated Kalman filter Coulomb counter into STM32 firmware; established BLE 5.0 advertising GATT service.',
    inProgress: 'Debugging OLED refresh stuttering when high-rate ADC interrupts fire; bench testing fault cut-off response.',
    blockersRisks: 'Interrupt priority collision between DMA SPI display update and ADC timer trigger.',
    proposedSolution: 'Lower OLED DMA interrupt priority and utilize double-buffering in background loop.',
    nextWeekPlan: 'Capture oscilloscope waveform traces for overcurrent cut-off; package release v0.9.5.',
    supportDecisionsRequired: 'Access to high-speed digital oscilloscope in Lab 3.',
    submittedAt: '2026-10-10T10:00:00Z',
    submittedBy: kishor.id
  });

  // Report 3: CEO Personal Weekly Report (SRS Section 2.3 & 7.2 requirement)
  const repCeo = db.weeklyReports.insertOne({
    id: 3,
    userId: ceo.id,
    periodStart: '2026-10-05',
    periodEnd: '2026-10-09',
    status: 'REVIEWED',
    currentVersion: 1,
    submittedAt: '2026-10-09T18:00:00Z',
    reviewedBy: admin.id,
    reviewedAt: '2026-10-10T09:00:00Z',
    reviewerFeedback: 'Q4 strategic targets well-aligned. Budget approved.',
    xpAwarded: 100
  });

  db.weeklyReportVersions.insertOne({
    id: 4,
    reportId: repCeo.id,
    versionNumber: 1,
    completedThisWeek: 'Conducted strategic investor briefing; approved capital expenditure for SMT prototyping line.',
    inProgress: 'Reviewing milestone acceptance standards across Power Station and AI Vision initiatives.',
    blockersRisks: 'Customs clearance lead times for imported thermal chambers.',
    nextWeekPlan: 'Executive milestone review for Milestone 3 (Firmware); sign supply agreements for battery cells.',
    submittedAt: '2026-10-09T18:00:00Z',
    submittedBy: ceo.id
  });

  // 8. Notifications
  db.notifications.insertOne({
    id: 1,
    recipientId: coo.id,
    type: 'MILESTONE_REVIEW',
    title: 'Milestone Ready for Review',
    body: 'kishor submitted Milestone 3 "Firmware and user interface" for review.',
    targetType: 'MILESTONE',
    targetId: m3.id,
    createdAt: '2026-10-10T16:05:00Z'
  });

  db.notifications.insertOne({
    id: 2,
    recipientId: coo.id,
    type: 'BLOCKER_ALERT',
    title: 'Critical Blocker Reported',
    body: 'Alex Chen reported a critical blocker on task "Power Board Rev B routing": Component supply shortage.',
    targetType: 'TASK',
    targetId: t3.id,
    createdAt: '2026-10-10T14:05:00Z'
  });

  db.notifications.insertOne({
    id: 3,
    recipientId: kishor.id,
    type: 'REVIEW_FEEDBACK',
    title: 'Weekly Report Changes Requested',
    body: 'Anita Roy requested additions to your Week report: "Please provide exact logic analyzer traces..."',
    targetType: 'WEEKLY_REPORT',
    targetId: repPriya.id,
    createdAt: '2026-10-10T14:02:00Z'
  });

  db.notifications.insertOne({
    id: 4,
    recipientId: alex.id,
    type: 'XP_GAIN',
    title: '⚡ +120 Innovation XP Awarded!',
    body: 'You unlocked the Blocker Buster achievement badge for proactive recovery planning.',
    targetType: 'USER',
    targetId: alex.id,
    createdAt: '2026-10-05T10:00:00Z'
  });

  // 9. Audit Events (SRS AUD-01)
  db.auditEvents.insertOne({
    id: 1,
    actorId: admin.id,
    action: 'USER_PROVISIONED',
    entityType: 'USER',
    entityId: alex.id,
    beforeSummary: 'None',
    afterSummary: 'User Alex Chen (Hardware Lead) created with EMPLOYEE role',
    reason: 'Onboarding new hardware engineering lead',
    timestamp: '2026-08-01T09:15:00Z'
  });

  db.auditEvents.insertOne({
    id: 2,
    actorId: ceo.id,
    action: 'PROJECT_CREATED',
    entityType: 'PROJECT',
    entityId: proj1.id,
    beforeSummary: 'None',
    afterSummary: 'Project PRJ-PPS-01 created with 8 milestones',
    reason: 'Kickoff of 2026 flagship energy platform',
    timestamp: '2026-08-01T10:00:00Z'
  });

  db.auditEvents.insertOne({
    id: 3,
    actorId: coo.id,
    action: 'MILESTONE_APPROVED',
    entityType: 'MILESTONE',
    entityId: m1.id,
    beforeSummary: 'Status: SUBMITTED_FOR_REVIEW',
    afterSummary: 'Status: APPROVED_COMPLETED, Reviewer: Anita Roy',
    reason: 'Passed thermal simulation margin checks and system specs',
    timestamp: '2026-08-19T14:30:00Z'
  });

  db.auditEvents.insertOne({
    id: 4,
    actorId: alex.id,
    action: 'SCHEDULE_CHANGE_REQUESTED',
    entityType: 'TASK',
    entityId: t3.id,
    beforeSummary: 'Due date: 2026-10-14',
    afterSummary: 'Proposed due date: 2026-10-18',
    reason: 'Vendor footprint modification requires extra thermal copper re-simulation',
    timestamp: '2026-10-10T15:30:00Z'
  });

  console.log('Seed completed successfully! All SRS demo entities created.');
}

if (require.main === module) {
  seedDatabase(true);
}

module.exports = { seedDatabase };

