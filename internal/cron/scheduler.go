package cron

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"crowdsec-manager/internal/backup"
	"crowdsec-manager/internal/logger"

	"github.com/robfig/cron/v3"
)

// Job represents a scheduled task
type Job struct {
	ID        string    `json:"id"`
	Schedule  string    `json:"schedule"`
	Task      string    `json:"task"`
	Enabled   bool      `json:"enabled"`
	LastRun   time.Time `json:"last_run,omitempty"`
	NextRun   time.Time `json:"next_run,omitempty"`
	EntryID   cron.EntryID `json:"-"`
}

// Scheduler manages cron jobs
type Scheduler struct {
	cron      *cron.Cron
	jobs      map[string]*Job
	mutex     sync.RWMutex
	filePath  string
	backupMgr *backup.Manager
}

// NewScheduler creates a new scheduler
func NewScheduler(dataPath string, backupMgr *backup.Manager) *Scheduler {
	return &Scheduler{
		cron:      cron.New(),
		jobs:      make(map[string]*Job),
		filePath:  filepath.Join(dataPath, "cron.json"),
		backupMgr: backupMgr,
	}
}

// Start starts the scheduler
func (s *Scheduler) Start() error {
	if err := s.load(); err != nil {
		logger.Warn("Failed to load cron jobs", "error", err)
	}

	s.cron.Start()
	logger.Info("Cron scheduler started")
	return nil
}

// Stop stops the scheduler
func (s *Scheduler) Stop() {
	s.cron.Stop()
	logger.Info("Cron scheduler stopped")
}

// AddJob adds a new job
func (s *Scheduler) AddJob(schedule, task string) (*Job, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	job := &Job{
		ID:       fmt.Sprintf("%d", time.Now().UnixNano()),
		Schedule: schedule,
		Task:     task,
		Enabled:  true,
	}

	if err := s.scheduleJob(job); err != nil {
		return nil, err
	}

	s.jobs[job.ID] = job
	if err := s.save(); err != nil {
		logger.Error("Failed to save cron jobs", "error", err)
	}

	return job, nil
}

// DeleteJob deletes a job
func (s *Scheduler) DeleteJob(id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	job, exists := s.jobs[id]
	if !exists {
		return fmt.Errorf("job not found")
	}

	s.cron.Remove(job.EntryID)
	delete(s.jobs, id)

	if err := s.save(); err != nil {
		return err
	}

	return nil
}

// ListJobs lists all jobs
func (s *Scheduler) ListJobs() []*Job {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	jobs := make([]*Job, 0, len(s.jobs))
	for _, job := range s.jobs {
		// Update next run time
		if entry := s.cron.Entry(job.EntryID); entry.ID != 0 {
			job.NextRun = entry.Next
		}
		jobs = append(jobs, job)
	}
	return jobs
}

func (s *Scheduler) scheduleJob(job *Job) error {
	var cmd func()

	switch job.Task {
	case "backup":
		cmd = func() {
			logger.Info("Running scheduled backup")
			if _, err := s.backupMgr.Create(false); err != nil {
				logger.Error("Scheduled backup failed", "error", err)
			}

			s.mutex.Lock()
			defer s.mutex.Unlock()
			job.LastRun = time.Now()
			if err := s.save(); err != nil {
				logger.Error("Failed to save cron state", "error", err)
			}
		}
	default:
		return fmt.Errorf("unknown task: %s", job.Task)
	}

	entryID, err := s.cron.AddFunc(job.Schedule, cmd)
	if err != nil {
		return fmt.Errorf("invalid schedule: %v", err)
	}

	job.EntryID = entryID
	return nil
}

func (s *Scheduler) load() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	data, err := os.ReadFile(s.filePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	var jobs []*Job
	if err := json.Unmarshal(data, &jobs); err != nil {
		return err
	}

	for _, job := range jobs {
		if job.Enabled {
			if err := s.scheduleJob(job); err != nil {
				logger.Warn("Failed to schedule loaded job", "id", job.ID, "error", err)
				continue
			}
		}
		s.jobs[job.ID] = job
	}

	return nil
}

func (s *Scheduler) save() error {
	// Note: mutex is already held by caller
	jobs := make([]*Job, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, job)
	}

	data, err := json.MarshalIndent(jobs, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.filePath, data, 0644)
}
