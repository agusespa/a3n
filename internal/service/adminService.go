package service

type AdminService interface {
}

type DefaultAdminService struct {
}

func NewDefaultAdminService() *DefaultAdminService {
	return &DefaultAdminService{}
}
