package proxy

import (
	"fmt"

	"github.com/arthurpanhku/gorial/internal/config"
	"github.com/arthurpanhku/gorial/internal/guard"
)

// buildGuards translates the declarative guard config into concrete guards.
func buildGuards(cfg *config.Config) ([]guard.Guard, error) {
	guards := make([]guard.Guard, 0, len(cfg.Guards))
	for _, gc := range cfg.Guards {
		action := guard.Action(gc.Action)
		dirs := parseDirections(gc.Apply)

		switch gc.Type {
		case "regex":
			g, err := guard.NewRegexGuard(gc.Name, action, dirs, gc.Patterns)
			if err != nil {
				return nil, fmt.Errorf("guard %q: %w", gc.Name, err)
			}
			guards = append(guards, g)
		case "pii":
			guards = append(guards, guard.NewPIIGuard(gc.Name, action, dirs))
		default:
			return nil, fmt.Errorf("guard %q: unknown type %q", gc.Name, gc.Type)
		}
	}
	return guards, nil
}

func parseDirections(apply []string) []guard.Direction {
	dirs := make([]guard.Direction, 0, len(apply))
	for _, d := range apply {
		dirs = append(dirs, guard.Direction(d))
	}
	return dirs
}
