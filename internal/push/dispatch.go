package push

import "context"

type Dispatcher struct {
	FCM  Sender
	APNs Sender
}

func (d Dispatcher) Send(ctx context.Context, platform, token string) error {
	var s Sender
	switch platform {
	case PlatformFCM:
		s = d.FCM
	case PlatformAPNs:
		s = d.APNs
	}
	if s == nil {
		return ErrPlatformUnavailable
	}
	return s.Send(ctx, platform, token)
}
