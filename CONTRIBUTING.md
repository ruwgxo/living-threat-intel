# Contributing to Living Threat Intelligence

Thank you for your interest in contributing! This project is both a technical book and a working threat intelligence platform.

## How to Contribute

### 📝 Book Content (chapters/, appendices/)

**Typos and Corrections**
- Open an issue or submit a PR directly
- Clearly describe the error and proposed fix
- Reference chapter number and section

**New Content / Chapters**
- Open an issue first to discuss
- Ensure it fits the book's scope and progression
- Follow the existing writing style (see chapters/STYLE_GUIDE.md)
- Include practical exercises with each chapter

**Content Improvements**
- Clarify confusing explanations
- Add real-world examples from recent breaches
- Update outdated CVE references or threat actor information
- Improve code examples

### 💻 Code (implementation/, deployment/)

**Bug Fixes**
- Open an issue describing the bug
- Submit PR with fix + test case
- Update relevant documentation

**New Features**
- Discuss in issues before coding
- Ensure it aligns with ThreatPulse architecture
- Add unit tests
- Update README and relevant chapters

**Code Quality**
- Follow PEP 8 style guide
- Use type hints (Python 3.11+)
- Include docstrings
- Add error handling
- Write tests

### 📊 Data Sources

**Adding New Threat Intel Sources**
- Ensure source is free and reliable
- Add to appendices/A-threat-intel-sources.md
- Provide example integration code
- Document API rate limits and authentication

### 🌍 Translations

Interested in translating to other languages?
- Open an issue to coordinate
- Create `chapters-[lang]/` directory
- Maintain consistent formatting
- Keep technical terms accurate

## Development Setup
```bash
# Clone repository
git clone https://github.com/ruwgxo/living-threat-intel.git
cd living-threat-intel

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest implementation/tests/

# Run collectors locally
python implementation/collectors/cisa_collector.py
```

## Code Review Process

1. **Submit PR** with clear description
2. **CI/CD runs**: Tests, linting, type checking
3. **Maintainer review**: Usually within 48 hours
4. **Iterate** based on feedback
5. **Merge** once approved

## Coding Standards

**Python**
- Python 3.11+
- Type hints for all functions
- Docstrings (Google style)
- Error handling with specific exceptions
- Logging instead of print statements

**Example:**
```python
from typing import Optional
import logging

logger = logging.getLogger(__name__)

def fetch_cisa_kev(date: Optional[str] = None) -> dict[str, Any]:
    """
    Fetch CISA Known Exploited Vulnerabilities.
    
    Args:
        date: Optional ISO format date (YYYY-MM-DD)
        
    Returns:
        Dictionary containing vulnerability data
        
    Raises:
        requests.HTTPError: If API request fails
        ValueError: If date format is invalid
    """
    try:
        # Implementation
        pass
    except requests.HTTPError as e:
        logger.error(f"CISA API error: {e}")
        raise
```

## Documentation Standards

**Chapters**
- Use CommonMark Markdown
- Include practical exercises
- Provide complete, runnable code examples
- Reference real CVEs and threat actors from 2024-2025
- Add "Further Reading" sections

**Code Comments**
- Explain WHY, not WHAT
- Document non-obvious decisions
- Link to relevant chapters or external resources

## Commit Messages

Follow conventional commits:
```
feat: add NVD API collector with rate limiting
fix: handle CISA API timeout errors
docs: update Chapter 5 with error handling examples
test: add unit tests for deduplication logic
refactor: improve categorizer performance
```

## Pull Request Template
```markdown
## Description
[What does this PR do?]

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Code refactoring
- [ ] Test improvement

## Testing
[How was this tested?]

## Checklist
- [ ] Code follows project style guidelines
- [ ] Added/updated tests
- [ ] Updated relevant documentation
- [ ] All tests pass locally
- [ ] No new warnings or errors

## Related Issues
Closes #[issue number]
```

## Questions?

- **General questions**: Open a GitHub Discussion
- **Bug reports**: Open an Issue
- **Feature requests**: Open an Issue with "enhancement" label

## Code of Conduct

- Be respectful and professional
- Assume positive intent
- Focus on constructive feedback
- Help newcomers learn
- Credit others' work appropriately

## Recognition

Contributors will be acknowledged in:
- README.md (if significant contribution)
- Book acknowledgments section
- Release notes

Thank you for contributing to Living Threat Intelligence! 🔐
